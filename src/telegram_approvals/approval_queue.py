"""The approval queue: request, authorize, decide, expire and audit."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import html
import logging
import re
import threading
import uuid
from collections import deque
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import NamedTuple, cast

from .errors import ApprovalError, ErrorCode
from .models import ApprovalEvent, ApprovalRequest, ApprovalState, AuditEntry, EventKind
from .transport import TelegramTransport

logger = logging.getLogger(__name__)

MAX_ACTION_UNITS = 200
MAX_SUMMARY_UNITS = 3000
MAX_CALLBACK_BYTES = 63
MIN_SECRET_BYTES = 32
MAC_BYTES = 18

_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,36}")
_CALLBACK_RE = re.compile(r"([ar]):([A-Za-z0-9_-]{1,36}):([A-Za-z0-9_-]{24})")

_APPROVED = "Approved"
_REJECTED = "Rejected"
_NOT_ALLOWED = "Not allowed"
_EXPIRED = "Expired"
_ALREADY = "Already decided"
_INVALID = "Invalid"

_MESSAGES: dict[ErrorCode, str] = {
    "malformed_callback": "malformed callback data",
    "unauthorized": "callback not authorized",
    "unknown_request": "unknown approval request",
    "expired": "approval request expired",
    "already_decided": "approval request already decided",
}


class _Outcome(NamedTuple):
    answer: str
    request: ApprovalRequest | None
    error: ApprovalError | None


def _default_id() -> str:
    return uuid.uuid4().hex


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _check_text(value: str, limit: int, field_name: str) -> None:
    if not isinstance(value, str):
        raise ApprovalError("invalid_config", f"{field_name} must be a string")
    if len(value) > limit or _utf16_units(value) > limit:
        raise ApprovalError("text_too_long", f"{field_name} exceeds {limit} UTF-16 code units")


def _escape(value: str) -> str:
    return html.escape(value, quote=False)


def _parse_callback(data: object) -> tuple[str, str, str] | None:
    if not isinstance(data, str) or len(data) > MAX_CALLBACK_BYTES:
        return None
    if len(data.encode("utf-8", "surrogatepass")) > MAX_CALLBACK_BYTES:
        return None
    match = _CALLBACK_RE.fullmatch(data)
    if match is None:
        return None
    verb, request_id, mac = match.groups()
    return verb, request_id, mac


class ApprovalQueue:
    """In-memory human approval queue.

    Args:
        transport: Where messages are sent; see :class:`TelegramTransport`.
        chat_id: Chat that receives approval messages.
        approver_ids: Telegram user ids allowed to decide (the presser, not the chat).
        secret: HMAC key, at least 32 bytes.
        clock: Returns the current timezone-aware time.
        ttl: How long a request stays decidable.
        id_factory: Produces request ids matching ``[A-Za-z0-9_-]{1,36}``.
        max_requests: Maximum stored requests; the oldest decided one is evicted at the cap.
        max_audit_entries: Maximum retained audit entries; the oldest are dropped.
        on_event: Optional observer receiving :class:`ApprovalEvent` values.

    Raises:
        ApprovalError: ``invalid_config`` for an unusable argument.
    """

    def __init__(
        self,
        transport: TelegramTransport,
        chat_id: int,
        approver_ids: frozenset[int],
        secret: bytes,
        clock: Callable[[], datetime],
        ttl: timedelta = timedelta(hours=1),
        id_factory: Callable[[], str] = _default_id,
        max_requests: int = 10_000,
        max_audit_entries: int = 10_000,
        on_event: Callable[[ApprovalEvent], None] | None = None,
    ) -> None:
        if not _is_int(chat_id):
            raise ApprovalError("invalid_config", "chat_id must be an integer")
        approvers = frozenset(approver_ids)
        if not approvers or not all(_is_int(a) for a in approvers):
            raise ApprovalError("invalid_config", "approver_ids must be a non-empty set of ints")
        if not isinstance(secret, bytes) or len(secret) < MIN_SECRET_BYTES:
            raise ApprovalError("invalid_config", "secret must be at least 32 bytes")
        if ttl <= timedelta(0):
            raise ApprovalError("invalid_config", "ttl must be positive")
        if max_requests < 1:
            raise ApprovalError("invalid_config", "max_requests must be at least 1")
        if max_audit_entries < 1:
            raise ApprovalError("invalid_config", "max_audit_entries must be at least 1")
        self._transport = transport
        self._chat_id = chat_id
        self._approvers = approvers
        self._secret = secret
        self._clock = clock
        self._ttl = ttl
        self._id_factory = id_factory
        self._max_requests = max_requests
        self._on_event = on_event
        self._requests: dict[str, ApprovalRequest] = {}
        self._audit: deque[AuditEntry] = deque(maxlen=max_audit_entries)
        self._lock = threading.RLock()

    def request(self, action: str, summary: str) -> ApprovalRequest:
        """Store a PENDING request and send it with Approve and Reject buttons.

        Raises:
            ApprovalError: ``text_too_long`` (action over 200 or summary over 3000 UTF-16 code
                units), ``too_many_pending``, ``transport_failed`` (nothing is stored) or
                ``invalid_config``.
        """
        _check_text(action, MAX_ACTION_UNITS, "action")
        _check_text(summary, MAX_SUMMARY_UNITS, "summary")
        with self._lock:
            request_id = self._id_factory()
            self._check_id(request_id)
            now = self._now()
            victim = self._eviction_victim()
            text = f"<b>{_escape(action)}</b>\n{_escape(summary)}"
            buttons = [
                ("Approve", self._callback_data("a", request_id)),
                ("Reject", self._callback_data("r", request_id)),
            ]
            try:
                message_id = self._transport.send_message(self._chat_id, text, buttons)
            except Exception as exc:
                raise ApprovalError("transport_failed", "send_message failed") from exc
            if victim is not None:
                del self._requests[victim]
            created = ApprovalRequest(
                id=request_id,
                action=action,
                summary=summary,
                created_at=now,
                expires_at=now + self._ttl,
                state=ApprovalState.PENDING,
                decided_by=None,
                decided_at=None,
                message_id=message_id,
            )
            self._requests[request_id] = created
            self._emit("requested", request_id, ApprovalState.PENDING, None, None)
            return created

    def handle_callback(
        self,
        callback_query_id: str,
        data: str,
        from_user_id: int,
    ) -> ApprovalRequest:
        """Process a button press and answer the callback query exactly once.

        The presser ``from_user_id`` (``callback_query.from.id``) is authorized, never the chat.

        Returns:
            The decided request.

        Raises:
            ApprovalError: ``malformed_callback``, ``unauthorized``, ``unknown_request``,
                ``expired``, ``already_decided`` or ``transport_failed`` (the decision and its
                audit entry are kept when only the message edit failed).
        """
        with self._lock:
            try:
                outcome = self._process(data, from_user_id)
            except ApprovalError as exc:
                outcome = _Outcome(_INVALID, None, exc)
        self._answer(callback_query_id, outcome.answer)
        if outcome.error is not None:
            raise outcome.error
        return cast(ApprovalRequest, outcome.request)

    def expire_due(self) -> list[ApprovalRequest]:
        """Expire every PENDING request whose ``expires_at`` has been reached.

        Only PENDING requests are touched and the transport is not called.
        """
        with self._lock:
            now = self._now()
            pending = [r for r in self._requests.values() if r.state is ApprovalState.PENDING]
            due = [r for r in pending if now >= r.expires_at]
            return [self._mark_expired(r, now) for r in due]

    def get(self, request_id: str) -> ApprovalRequest:
        """Return a stored request.

        Raises:
            ApprovalError: ``unknown_request`` if it is not stored (or was evicted).
        """
        with self._lock:
            found = self._requests.get(request_id) if isinstance(request_id, str) else None
        if found is None:
            raise ApprovalError("unknown_request", _MESSAGES["unknown_request"])
        return found

    def audit_log(self) -> list[AuditEntry]:
        """Return a copy of the retained audit entries, oldest first."""
        with self._lock:
            return list(self._audit)

    def _now(self) -> datetime:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise ApprovalError("invalid_config", "clock must return timezone-aware datetimes")
        return now

    def _mac(self, verb: str, request_id: str) -> str:
        message = f"{verb}:{request_id}".encode()
        digest = hmac.new(self._secret, message, hashlib.sha256).digest()[:MAC_BYTES]
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _callback_data(self, verb: str, request_id: str) -> str:
        return f"{verb}:{request_id}:{self._mac(verb, request_id)}"

    def _check_id(self, request_id: str) -> None:
        if not isinstance(request_id, str) or _ID_RE.fullmatch(request_id) is None:
            raise ApprovalError("invalid_config", "id_factory returned an invalid id")
        if request_id in self._requests:
            raise ApprovalError("invalid_config", "id_factory returned a duplicate id")

    def _eviction_victim(self) -> str | None:
        if len(self._requests) < self._max_requests:
            return None
        decided = [(r.decided_at, r.id) for r in self._requests.values() if r.decided_at]
        if not decided:
            raise ApprovalError("too_many_pending", "too many pending approval requests")
        return min(decided, key=lambda pair: pair[0])[1]

    def _emit(
        self,
        kind: EventKind,
        request_id: str | None,
        state: ApprovalState | None,
        actor_id: int | None,
        code: ErrorCode | None,
    ) -> None:
        if self._on_event is None:
            return
        event = ApprovalEvent(kind, request_id, state, actor_id, code)
        try:
            self._on_event(event)
        except Exception as exc:
            logger.warning("on_event handler failed: %s", type(exc).__name__)

    def _answer(self, callback_query_id: str, text: str) -> None:
        try:
            self._transport.answer_callback(callback_query_id, text)
        except Exception as exc:
            logger.warning("answer_callback failed: %s", type(exc).__name__)

    def _reject(
        self,
        code: ErrorCode,
        answer: str,
        request_id: str | None,
        state: ApprovalState | None,
        actor: int | None,
    ) -> _Outcome:
        self._emit("callback_rejected", request_id, state, actor, code)
        return _Outcome(answer, None, ApprovalError(code, _MESSAGES[code]))

    def _mark_expired(self, current: ApprovalRequest, now: datetime) -> ApprovalRequest:
        expired = dataclasses.replace(current, state=ApprovalState.EXPIRED, decided_at=now)
        self._requests[expired.id] = expired
        self._audit.append(AuditEntry(expired.id, None, current.state, ApprovalState.EXPIRED, now))
        logger.info("approval %s expired", expired.id)
        self._emit("expired", expired.id, ApprovalState.EXPIRED, None, None)
        return expired

    def _process(self, data: str, user_id: int) -> _Outcome:
        actor = user_id if _is_int(user_id) else None
        parsed = _parse_callback(data)
        if parsed is None:
            return self._reject("malformed_callback", _INVALID, None, None, actor)
        verb, request_id, mac = parsed
        expected = self._mac(verb, request_id)
        if not hmac.compare_digest(mac.encode("ascii"), expected.encode("ascii")):
            return self._reject("unauthorized", _NOT_ALLOWED, None, None, actor)
        current = self._requests.get(request_id)
        state = None if current is None else current.state
        if actor is None or actor not in self._approvers:
            return self._reject("unauthorized", _NOT_ALLOWED, request_id, state, actor)
        if current is None:
            return self._reject("unknown_request", _INVALID, request_id, None, actor)
        if current.state is ApprovalState.EXPIRED:
            return self._reject("expired", _EXPIRED, request_id, current.state, actor)
        if current.state is not ApprovalState.PENDING:
            return self._reject("already_decided", _ALREADY, request_id, current.state, actor)
        now = self._now()
        if now >= current.expires_at:
            self._mark_expired(current, now)
            return _Outcome(_EXPIRED, None, ApprovalError("expired", _MESSAGES["expired"]))
        return self._decide(current, verb, actor, now)

    def _decide(self, current: ApprovalRequest, verb: str, actor: int, now: datetime) -> _Outcome:
        new_state = ApprovalState.APPROVED if verb == "a" else ApprovalState.REJECTED
        decided = dataclasses.replace(current, state=new_state, decided_by=actor, decided_at=now)
        self._requests[decided.id] = decided
        self._audit.append(AuditEntry(decided.id, actor, current.state, new_state, now))
        logger.info("approval %s decided: %s", decided.id, new_state.name)
        self._emit("decided", decided.id, new_state, actor, None)
        answer = _APPROVED if new_state is ApprovalState.APPROVED else _REJECTED
        text = f"{_escape(decided.summary)}\n\n<b>{new_state.name}</b> by {actor}"
        message_id = cast(int, decided.message_id)
        try:
            self._transport.edit_message(self._chat_id, message_id, text)
        except Exception as exc:
            error = ApprovalError("transport_failed", "edit_message failed")
            error.__cause__ = exc
            return _Outcome(answer, decided, error)
        return _Outcome(answer, decided, None)
