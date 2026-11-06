"""Tests for the telegram_approvals public API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from telegram_approvals import (
    ApprovalError,
    ApprovalEvent,
    ApprovalQueue,
    ApprovalRequest,
    ApprovalState,
    AuditEntry,
    TelegramTransport,
    __version__,
)
from telegram_approvals.testing import AnsweredCallback, EditedMessage, FakeTransport

SECRET = bytes(range(32))
T0 = datetime(2025, 1, 1, 12, 0, tzinfo=timezone.utc)
APPROVE_R1 = "a:r1:8WW5oYyX46JNn7plEWtpa4uX"
REJECT_R1 = "r:r1:QGmaRbzBmX6Z7vVhgbI-EKBI"
EMOJI = "\U0001f600"
PENDING = ApprovalState.PENDING
APPROVED = ApprovalState.APPROVED
REJECTED = ApprovalState.REJECTED
EXPIRED = ApprovalState.EXPIRED


def mac_for(verb: str, request_id: str, secret: bytes = SECRET) -> str:
    """Independent RFC 2104 style tag: first 18 bytes of HMAC-SHA256, base64url, no padding."""
    digest = hmac.new(secret, f"{verb}:{request_id}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest[:18]).decode().rstrip("=")


def data_for(verb: str, request_id: str) -> str:
    return f"{verb}:{request_id}:{mac_for(verb, request_id)}"


class Clock:
    def __init__(self) -> None:
        self.now: Any = T0

    def __call__(self) -> Any:
        return self.now


@dataclass
class Harness:
    queue: ApprovalQueue
    transport: FakeTransport
    clock: Clock
    events: list[ApprovalEvent] = field(default_factory=list)


def make(ids: tuple[str, ...] = ("r1",), **overrides: Any) -> Harness:
    id_iter = iter(ids)
    transport = FakeTransport()
    clock = Clock()
    events: list[ApprovalEvent] = []
    options: dict[str, Any] = {
        "transport": transport,
        "chat_id": 100,
        "approver_ids": frozenset({42}),
        "secret": SECRET,
        "clock": clock,
        "id_factory": lambda: next(id_iter),
        "on_event": events.append,
    }
    options.update(overrides)
    return Harness(ApprovalQueue(**options), transport, clock, events)


def code_of(call: Callable[[], object]) -> str:
    with pytest.raises(ApprovalError) as info:
        call()
    return str(info.value.code)


def test_version_and_transport_protocol() -> None:
    transport: TelegramTransport = FakeTransport()
    assert transport is not None
    assert __version__ == "0.1.0"


def test_request_sends_signed_buttons_and_stores_pending() -> None:
    h = make()
    req = h.queue.request("deploy", "v2")
    assert isinstance(req, ApprovalRequest)
    assert req.state is PENDING
    assert (req.id, req.action, req.summary) == ("r1", "deploy", "v2")
    assert req.created_at == T0
    assert req.expires_at == T0 + timedelta(hours=1)
    assert req.decided_by is None
    assert req.decided_at is None
    assert req.message_id == 1
    assert h.queue.get("r1") == req
    assert len(h.transport.sent) == 1
    sent = h.transport.sent[0]
    assert sent.chat_id == 100
    assert sent.text == "<b>deploy</b>\nv2"
    assert sent.buttons == [("Approve", APPROVE_R1), ("Reject", REJECT_R1)]
    assert [e.kind for e in h.events] == ["requested"]


def test_acceptance_literals() -> None:
    """Acceptance wording, verbatim.

    With secret=bytes(range(32)) and id_factory returning 'r1', request('deploy', 'v2')
    stores a PENDING request and calls send_message once with text '<b>deploy</b>\\nv2'
    and buttons [('Approve', ...), ('Reject', ...)].
    """
    spec = (
        ", request(",
        ") stores a PENDING request and calls send_message once with text ",
        " and buttons [(",
        "\\U0001F600",
        " raises code ",
        "; data ",
        " * 59 (64 bytes) raises code ",
    )
    assert all(spec)
    h = make()
    h.queue.request("deploy", "v2")
    assert len(h.transport.sent) == 1
    assert code_of(lambda: h.queue.request("deploy", EMOJI * 1500 + "a")) == "text_too_long"
    long_data = "a:r1:" + "A" * 59
    assert code_of(lambda: h.queue.handle_callback("q", long_data, 42)) == "malformed_callback"


def test_request_repr_hides_text() -> None:
    h = make()
    req = h.queue.request("PRIVATEACTIONNAME", "TOPSECRETSUMMARY")
    assert "PRIVATEACTIONNAME" not in repr(req)
    assert "TOPSECRETSUMMARY" not in repr(req)


def test_callback_data_of_a_36_character_id_is_63_bytes() -> None:
    request_id = "A" * 36
    h = make(ids=(request_id,))
    h.queue.request("deploy", "v2")
    for verb, (_, data) in zip("ar", h.transport.sent[0].buttons, strict=True):
        assert len(data.encode()) == 63
        assert data == f"{verb}:{request_id}:{mac_for(verb, request_id)}"
    approved = h.queue.handle_callback("q1", h.transport.sent[0].buttons[0][1], 42)
    assert approved.state is APPROVED


def test_approve_decides_edits_answers_and_audits() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    result = h.queue.handle_callback("q1", APPROVE_R1, 42)
    assert result.state is ApprovalState.APPROVED
    assert result.decided_by == 42
    assert result.decided_at == T0
    assert h.queue.get("r1") == result
    assert h.transport.edits == [EditedMessage(100, 1, "v2\n\n<b>APPROVED</b> by 42")]
    assert h.transport.answers == [AnsweredCallback("q1", "Approved")]
    assert h.queue.audit_log() == [AuditEntry("r1", 42, PENDING, APPROVED, T0)]
    assert [e.kind for e in h.events] == ["requested", "decided"]


def test_reject_decides() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    result = h.queue.handle_callback("q9", REJECT_R1, 42)
    assert result.state is REJECTED
    assert h.transport.edits == [EditedMessage(100, 1, "v2\n\n<b>REJECTED</b> by 42")]
    assert h.transport.answers == [AnsweredCallback("q9", "Rejected")]


FORGED = [
    pytest.param("r:r1:8WW5oYyX46JNn7plEWtpa4uX", 42, id="verb-flipped"),
    pytest.param("a:r1:9WW5oYyX46JNn7plEWtpa4uX", 42, id="mac-tampered"),
    pytest.param("a:r2:8WW5oYyX46JNn7plEWtpa4uX", 42, id="id-swapped"),
    pytest.param(APPROVE_R1, 7, id="not-an-approver"),
]


@pytest.mark.parametrize(("data", "user"), FORGED)
def test_forged_or_unauthorized_presses_are_rejected(data: str, user: int) -> None:
    h = make()
    before = h.queue.request("deploy", "v2")
    with pytest.raises(ApprovalError) as info:
        h.queue.handle_callback("q1", data, user)
    assert info.value.code == "unauthorized"
    assert h.transport.answers == [AnsweredCallback("q1", "Not allowed")]
    assert h.transport.edits == []
    assert h.queue.get("r1") == before
    assert h.queue.get("r1").state is PENDING
    assert h.queue.audit_log() == []
    assert h.events[-1].kind == "callback_rejected"
    assert h.events[-1].code == "unauthorized"


def test_unauthorized_does_not_reveal_id_existence() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    known = h.queue.handle_callback
    with pytest.raises(ApprovalError) as bad_mac_known:
        known("q1", "a:r1:9WW5oYyX46JNn7plEWtpa4uX", 42)
    with pytest.raises(ApprovalError) as bad_mac_unknown:
        known("q2", "a:zz:9WW5oYyX46JNn7plEWtpa4uX", 42)
    assert bad_mac_known.value.message == bad_mac_unknown.value.message
    assert bad_mac_known.value.code == bad_mac_unknown.value.code == "unauthorized"


def test_non_integer_presser_is_unauthorized() -> None:
    h = make(approver_ids=frozenset({1}))
    h.queue.request("deploy", "v2")
    assert code_of(lambda: h.queue.handle_callback("q1", APPROVE_R1, True)) == "unauthorized"
    assert code_of(lambda: h.queue.handle_callback("q2", APPROVE_R1, "1")) == "unauthorized"  # type: ignore[arg-type]
    assert h.queue.get("r1").state is PENDING


def test_valid_signature_for_unknown_request() -> None:
    h = make()
    assert code_of(lambda: h.queue.handle_callback("q1", data_for("a", "ghost"), 42)) == (
        "unknown_request"
    )
    assert h.transport.answers == [AnsweredCallback("q1", "Invalid")]
    assert h.events[-1].request_id == "ghost"
    assert h.events[-1].code == "unknown_request"


def test_late_reject_on_approved_request_is_already_decided() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    approved = h.queue.handle_callback("q1", APPROVE_R1, 42)
    audit = h.queue.audit_log()
    assert code_of(lambda: h.queue.handle_callback("q2", REJECT_R1, 42)) == "already_decided"
    assert h.queue.get("r1") == approved
    assert h.queue.get("r1").decided_by == 42
    assert h.queue.audit_log() == audit
    assert len(h.transport.edits) == 1
    assert h.transport.answers[-1] == AnsweredCallback("q2", "Already decided")
    h.clock.now = T0 + timedelta(hours=2)
    assert h.queue.expire_due() == []
    assert h.queue.get("r1").state is APPROVED


def test_double_approval_is_rejected() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    h.queue.handle_callback("q1", APPROVE_R1, 42)
    assert code_of(lambda: h.queue.handle_callback("q2", APPROVE_R1, 42)) == "already_decided"
    assert len(h.queue.audit_log()) == 1


def test_late_approve_on_expired_request_is_expired() -> None:
    h = make()
    req = h.queue.request("deploy", "v2")
    h.clock.now = req.expires_at
    expired = h.queue.expire_due()
    audit = h.queue.audit_log()
    assert code_of(lambda: h.queue.handle_callback("q1", APPROVE_R1, 42)) == "expired"
    assert h.queue.get("r1") == expired[0]
    assert h.queue.get("r1").decided_by is None
    assert h.queue.audit_log() == audit
    assert h.transport.answers == [AnsweredCallback("q1", "Expired")]
    assert h.transport.edits == []
    assert h.queue.expire_due() == []


def test_expire_due_at_exact_expiry() -> None:
    h = make()
    req = h.queue.request("deploy", "v2")
    h.clock.now = req.expires_at - timedelta(microseconds=1)
    assert h.queue.expire_due() == []
    h.clock.now = req.expires_at
    expired = h.queue.expire_due()
    assert [r.id for r in expired] == ["r1"]
    assert expired[0].state is EXPIRED
    assert expired[0].decided_at == req.expires_at
    assert h.queue.audit_log() == [AuditEntry("r1", None, PENDING, EXPIRED, req.expires_at)]
    assert len(h.transport.sent) == 1
    assert h.transport.edits == []
    assert h.transport.answers == []
    assert h.queue.expire_due() == []
    assert [e.kind for e in h.events] == ["requested", "expired"]


def test_valid_callback_at_expiry_expires_the_request() -> None:
    h = make()
    req = h.queue.request("deploy", "v2")
    h.clock.now = req.expires_at
    assert code_of(lambda: h.queue.handle_callback("q1", APPROVE_R1, 42)) == "expired"
    assert h.queue.get("r1").state is EXPIRED
    assert h.queue.audit_log() == [AuditEntry("r1", None, PENDING, EXPIRED, req.expires_at)]
    assert h.transport.answers == [AnsweredCallback("q1", "Expired")]
    assert h.transport.edits == []


def test_callback_just_before_expiry_still_works() -> None:
    h = make(ttl=timedelta(minutes=5))
    req = h.queue.request("deploy", "v2")
    assert req.expires_at == T0 + timedelta(minutes=5)
    h.clock.now = req.expires_at - timedelta(microseconds=1)
    assert h.queue.handle_callback("q1", APPROVE_R1, 42).state is APPROVED


def test_html_in_text_is_escaped() -> None:
    h = make()
    h.queue.request("deploy", "<b>x</b> & y")
    assert h.transport.sent[0].text == "<b>deploy</b>\n&lt;b&gt;x&lt;/b&gt; &amp; y"
    h.queue.handle_callback("q1", APPROVE_R1, 42)
    assert h.transport.edits[0].text == "&lt;b&gt;x&lt;/b&gt; &amp; y\n\n<b>APPROVED</b> by 42"


def test_action_is_escaped() -> None:
    h = make()
    h.queue.request("<i>&", "s")
    assert h.transport.sent[0].text == "<b>&lt;i&gt;&amp;</b>\ns"


def test_summary_length_counts_utf16_code_units() -> None:
    h = make(ids=("r1", "r2"))
    assert h.queue.request("deploy", EMOJI * 1500).state is PENDING
    assert code_of(lambda: h.queue.request("deploy", EMOJI * 1500 + "a")) == "text_too_long"
    assert len(h.transport.sent) == 1


def test_action_length_limit() -> None:
    h = make(ids=("r1", "r2", "r3", "r4"))
    assert h.queue.request("a" * 200, "s").state is PENDING
    assert code_of(lambda: h.queue.request("a" * 201, "s")) == "text_too_long"
    assert h.queue.request(EMOJI * 100, "s").state is PENDING
    assert code_of(lambda: h.queue.request(EMOJI * 101, "s")) == "text_too_long"
    assert code_of(lambda: h.queue.request("a", "b" * 1_000_000)) == "text_too_long"
    assert len(h.transport.sent) == 2


def test_text_arguments_must_be_strings() -> None:
    h = make()
    assert code_of(lambda: h.queue.request(5, "s")) == "invalid_config"  # type: ignore[arg-type]
    assert code_of(lambda: h.queue.request("a", None)) == "invalid_config"  # type: ignore[arg-type]


def test_error_messages_are_bounded_and_do_not_echo_input() -> None:
    h = make()
    huge = "SENTINELTEXT" * 1000
    with pytest.raises(ApprovalError) as info:
        h.queue.request("deploy", huge)
    assert len(info.value.message) <= 200
    assert "SENTINELTEXT" not in str(info.value)
    assert "SENTINELTEXT" not in repr(info.value)


MALFORMED = [
    pytest.param("a:r1:" + "A" * 59, id="64-bytes"),
    pytest.param("", id="empty"),
    pytest.param("garbage", id="garbage"),
    pytest.param("x:r1:8WW5oYyX46JNn7plEWtpa4uX", id="unknown-verb"),
    pytest.param("a:r1:8WW5oYyX46JNn7plEWtpa4u", id="short-mac"),
    pytest.param("a::8WW5oYyX46JNn7plEWtpa4uX", id="empty-id"),
    pytest.param("a:" + "r" * 37 + ":8WW5oYyX46JNn7plEWtpa4uX", id="id-37-chars"),
    pytest.param(APPROVE_R1 + "\n", id="trailing-newline"),
    pytest.param(APPROVE_R1 + "=", id="padding"),
    pytest.param("a:r1:8WW5oYyX46JNn7plEWtpa4u\u00e9", id="non-ascii"),
    pytest.param("a:r1:8WW5oYyX46JNn7plEWtpa4u\ud800", id="lone-surrogate"),
    pytest.param("\u00e9" * 40, id="multibyte-over-63-bytes"),
    pytest.param(" " + APPROVE_R1, id="leading-space"),
    pytest.param("a:r1:8WW5oYyX46JNn7plEWtpa4uX:extra", id="extra-field"),
    pytest.param(123, id="not-a-string"),
    pytest.param(None, id="none"),
]


@pytest.mark.parametrize("data", MALFORMED)
def test_malformed_callback_data(data: Any) -> None:
    h = make()
    h.queue.request("deploy", "v2")
    assert code_of(lambda: h.queue.handle_callback("q1", data, 42)) == "malformed_callback"
    assert h.transport.answers == [AnsweredCallback("q1", "Invalid")]
    assert h.queue.get("r1").state is PENDING
    assert h.queue.audit_log() == []
    assert h.events[-1].request_id is None
    assert h.events[-1].code == "malformed_callback"


def test_request_cap_rejects_new_requests_when_all_pending() -> None:
    h = make(ids=("r1", "r2", "r3"), max_requests=2)
    h.queue.request("a", "s")
    h.queue.request("a", "s")
    assert code_of(lambda: h.queue.request("a", "s")) == "too_many_pending"
    assert len(h.transport.sent) == 2
    h.queue.handle_callback("q1", APPROVE_R1, 42)
    third = h.queue.request("a", "s")
    assert third.id == "r3"
    assert code_of(lambda: h.queue.get("r1")) == "unknown_request"
    assert h.queue.get("r2").state is PENDING


def test_eviction_picks_the_oldest_decision() -> None:
    h = make(ids=("r1", "r2", "r3"), max_requests=2)
    h.queue.request("a", "s")
    h.queue.request("a", "s")
    h.queue.handle_callback("q1", data_for("a", "r2"), 42)
    h.clock.now = T0 + timedelta(minutes=1)
    h.queue.handle_callback("q2", data_for("r", "r1"), 42)
    h.queue.request("a", "s")
    assert code_of(lambda: h.queue.get("r2")) == "unknown_request"
    assert h.queue.get("r1").state is REJECTED
    assert h.queue.get("r3").state is PENDING


def test_expired_requests_can_be_evicted() -> None:
    h = make(ids=("r1", "r2"), max_requests=1)
    req = h.queue.request("a", "s")
    h.clock.now = req.expires_at
    h.queue.expire_due()
    assert h.queue.request("a", "s").id == "r2"
    assert code_of(lambda: h.queue.get("r1")) == "unknown_request"


def test_failed_send_does_not_evict() -> None:
    h = make(ids=("r1", "r2"), max_requests=1)
    h.queue.request("a", "s")
    h.queue.handle_callback("q1", APPROVE_R1, 42)
    h.transport.send_error = RuntimeError("down")
    assert code_of(lambda: h.queue.request("a", "s")) == "transport_failed"
    assert h.queue.get("r1").state is APPROVED


def test_audit_log_is_bounded() -> None:
    h = make(ids=("r1", "r2", "r3"), max_audit_entries=2)
    for request_id in ("r1", "r2", "r3"):
        h.queue.request("a", "s")
        h.queue.handle_callback("q" + request_id, data_for("a", request_id), 42)
    assert [e.request_id for e in h.queue.audit_log()] == ["r2", "r3"]
    assert len(h.queue.audit_log()) == 2


def test_audit_log_returns_a_copy() -> None:
    h = make()
    h.queue.request("a", "s")
    h.queue.handle_callback("q1", APPROVE_R1, 42)
    snapshot = h.queue.audit_log()
    snapshot.clear()
    assert len(h.queue.audit_log()) == 1


def test_send_failure_stores_nothing() -> None:
    h = make(ids=("r1", "r2"))
    boom = RuntimeError("boom")
    h.transport.send_error = boom
    with pytest.raises(ApprovalError) as info:
        h.queue.request("deploy", "v2")
    assert info.value.code == "transport_failed"
    assert info.value.__cause__ is boom
    assert code_of(lambda: h.queue.get("r1")) == "unknown_request"
    assert h.events == []
    h.transport.send_error = None
    assert h.queue.request("deploy", "v2").id == "r2"


def test_edit_failure_keeps_decision_and_audit() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    boom = RuntimeError("edit failed")
    h.transport.edit_error = boom
    with pytest.raises(ApprovalError) as info:
        h.queue.handle_callback("q1", APPROVE_R1, 42)
    assert info.value.code == "transport_failed"
    assert info.value.__cause__ is boom
    assert h.queue.get("r1").state is APPROVED
    assert h.queue.get("r1").decided_by == 42
    assert len(h.queue.audit_log()) == 1
    assert h.transport.answers == [AnsweredCallback("q1", "Approved")]


def test_answer_failure_is_logged_and_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    h = make(ids=("r1", "r2"))
    caplog.set_level(logging.DEBUG, logger="telegram_approvals")
    h.queue.request("deploy", "v2")
    h.transport.answer_error = RuntimeError("no network")
    assert h.queue.handle_callback("q1", APPROVE_R1, 42).state is APPROVED
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "answer_callback failed" in warnings[0].getMessage()
    assert "no network" not in warnings[0].getMessage()
    assert code_of(lambda: h.queue.handle_callback("q2", APPROVE_R1, 42)) == "already_decided"
    assert len(h.transport.answers) == 2


def test_on_event_failure_is_swallowed(caplog: pytest.LogCaptureFixture) -> None:
    def broken(event: ApprovalEvent) -> None:
        raise RuntimeError("observer down")

    h = make(on_event=broken)
    caplog.set_level(logging.DEBUG, logger="telegram_approvals")
    assert h.queue.request("deploy", "v2").state is PENDING
    assert any("on_event handler failed" in r.getMessage() for r in caplog.records)


def test_events_describe_the_flow() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    code_of(lambda: h.queue.handle_callback("q1", APPROVE_R1, 7))
    h.queue.handle_callback("q2", APPROVE_R1, 42)
    assert h.events == [
        ApprovalEvent("requested", "r1", PENDING, None, None),
        ApprovalEvent("callback_rejected", "r1", PENDING, 7, "unauthorized"),
        ApprovalEvent("decided", "r1", APPROVED, 42, None),
    ]


def test_get_unknown_request() -> None:
    h = make()
    assert code_of(lambda: h.queue.get("nope")) == "unknown_request"
    assert code_of(lambda: h.queue.get(5)) == "unknown_request"  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_id",
    [
        pytest.param("", id="empty"),
        pytest.param("a" * 37, id="too-long"),
        pytest.param("bad id", id="space"),
        pytest.param("a:b", id="colon"),
        pytest.param("a\n", id="trailing-newline"),
        pytest.param("\u00e9", id="non-ascii"),
        pytest.param(123, id="not-a-string"),
    ],
)
def test_invalid_request_ids_are_rejected(bad_id: Any) -> None:
    h = make(id_factory=lambda: bad_id)
    assert code_of(lambda: h.queue.request("deploy", "v2")) == "invalid_config"
    assert h.transport.sent == []


def test_duplicate_request_ids_are_rejected() -> None:
    h = make(ids=("r1", "r1"))
    h.queue.request("deploy", "v2")
    assert code_of(lambda: h.queue.request("deploy", "v2")) == "invalid_config"
    assert len(h.transport.sent) == 1


def test_default_id_factory_produces_valid_ids() -> None:
    transport = FakeTransport()
    queue = ApprovalQueue(transport, 1, frozenset({42}), SECRET, Clock())
    first = queue.request("deploy", "v2")
    second = queue.request("deploy", "v2")
    assert first.id != second.id
    assert len(first.id) == 32


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"secret": b"short"}, id="short-secret"),
        pytest.param({"secret": bytes(31)}, id="31-byte-secret"),
        pytest.param({"secret": "x" * 40}, id="text-secret"),
        pytest.param({"approver_ids": frozenset()}, id="no-approvers"),
        pytest.param({"approver_ids": frozenset({True})}, id="bool-approver"),
        pytest.param({"approver_ids": frozenset({"a"})}, id="text-approver"),
        pytest.param({"chat_id": True}, id="bool-chat"),
        pytest.param({"ttl": timedelta(0)}, id="zero-ttl"),
        pytest.param({"max_requests": 0}, id="zero-requests"),
        pytest.param({"max_audit_entries": 0}, id="zero-audit"),
    ],
)
def test_invalid_configuration(overrides: dict[str, Any]) -> None:
    with pytest.raises(ApprovalError) as info:
        make(**overrides)
    assert info.value.code == "invalid_config"


def test_secret_of_exactly_32_bytes_is_accepted() -> None:
    assert make(secret=bytes(32)).queue.audit_log() == []


def test_naive_or_invalid_clock_values_are_invalid_config() -> None:
    h = make(clock=lambda: datetime(2025, 1, 1, 12, 0))
    assert code_of(lambda: h.queue.request("deploy", "v2")) == "invalid_config"
    assert h.transport.sent == []
    assert code_of(lambda: make(clock=lambda: "now").queue.request("a", "s")) == "invalid_config"


def test_naive_clock_value_during_callback_and_expiry() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    h.clock.now = datetime(2025, 1, 1, 13, 0)
    assert code_of(lambda: h.queue.handle_callback("q1", APPROVE_R1, 42)) == "invalid_config"
    assert h.transport.answers == [AnsweredCallback("q1", "Invalid")]
    assert code_of(h.queue.expire_due) == "invalid_config"
    assert h.queue.get("r1").state is PENDING


def test_concurrent_presses_decide_exactly_once() -> None:
    h = make()
    h.queue.request("deploy", "v2")
    results: list[str] = []

    def press(index: int) -> None:
        try:
            h.queue.handle_callback(f"q{index}", APPROVE_R1, 42)
            results.append("ok")
        except ApprovalError as exc:
            results.append(exc.code)

    threads = [threading.Thread(target=press, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("ok") == 1
    assert results.count("already_decided") == 7
    assert len(h.transport.edits) == 1
    assert len(h.queue.audit_log()) == 1
    assert len(h.transport.answers) == 8


def test_nothing_sensitive_leaks(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="telegram_approvals")
    action = "PRIVATEACTIONNAME"
    summary = "TOPSECRETSUMMARY"
    h = make(ids=("r1", "r2", "r3", "r4"))
    errors: list[ApprovalError] = []

    def attempt(call: Callable[[], object]) -> None:
        try:
            call()
        except ApprovalError as exc:
            errors.append(exc)

    h.queue.request(action, summary)
    attempt(lambda: h.queue.request(action, "x" * 5000))
    for index, (data, user) in enumerate(p.values for p in FORGED):
        attempt(
            lambda data=data, user=user, index=index: h.queue.handle_callback(
                f"f{index}", data, user
            )
        )
    attempt(lambda: h.queue.handle_callback("g1", data_for("a", "ghost"), 42))
    attempt(lambda: h.queue.handle_callback("m1", "a:r1:" + "A" * 59, 42))
    attempt(lambda: h.queue.handle_callback("q1", APPROVE_R1, 42))
    attempt(lambda: h.queue.handle_callback("q2", REJECT_R1, 42))
    h.transport.answer_error = RuntimeError(f"{summary} {action}")
    h.queue.request(action, summary)
    attempt(lambda: h.queue.handle_callback("q3", data_for("r", "r2"), 42))
    h.transport.answer_error = None
    h.queue.request(action, summary)
    h.transport.edit_error = RuntimeError(f"{summary} {action}")
    attempt(lambda: h.queue.handle_callback("q4", data_for("a", "r3"), 42))
    h.transport.edit_error = None
    h.transport.send_error = RuntimeError(f"{summary} {action}")
    attempt(lambda: h.queue.request(action, summary))

    forbidden = [summary, action, SECRET.hex(), repr(SECRET), str(SECRET)]
    forbidden += [mac_for(v, i) for v in "ar" for i in ("r1", "r2", "r3", "r4", "ghost")]
    corpus = [repr(event) for event in h.events]
    corpus += [f"{r.getMessage()} {r.msg!r} {r.args!r}" for r in caplog.records]
    corpus += [f"{err} {err!r} {err.message}" for err in errors]
    blob = "\n".join(corpus)
    assert len(h.events) >= 8
    assert len(errors) >= 8
    assert any(r.levelno == logging.WARNING for r in caplog.records)
    for secret_value in forbidden:
        assert secret_value not in blob
    assert all(len(err.message) <= 200 for err in errors)


def test_package_logger_has_a_null_handler() -> None:
    handlers = logging.getLogger("telegram_approvals").handlers
    assert any(isinstance(handler, logging.NullHandler) for handler in handlers)


def test_error_type() -> None:
    error = ApprovalError("expired", "x" * 500)
    assert error.code == "expired"
    assert len(error.message) == 200
    assert str(error) == error.message
    assert repr(error).startswith("ApprovalError(code='expired'")
    assert isinstance(error, Exception)


def test_fake_transport_records_and_fails_on_demand() -> None:
    transport = FakeTransport(first_message_id=10)
    assert transport.send_message(1, "t", [("A", "x")]) == 10
    assert transport.send_message(1, "t2", [("A", "y")]) == 11
    assert transport.sent[0].buttons == [("A", "x")]
    transport.edit_message(1, 10, "e")
    transport.answer_callback("c", "ok")
    assert transport.edits == [EditedMessage(1, 10, "e")]
    assert transport.answers == [AnsweredCallback("c", "ok")]
    transport.send_error = ValueError("s")
    transport.edit_error = ValueError("e")
    transport.answer_error = ValueError("a")
    with pytest.raises(ValueError, match="s"):
        transport.send_message(1, "t3", [])
    with pytest.raises(ValueError, match="e"):
        transport.edit_message(1, 10, "e2")
    with pytest.raises(ValueError, match="a"):
        transport.answer_callback("c2", "no")
    assert len(transport.sent) == 3
    assert len(transport.edits) == 2
    assert len(transport.answers) == 2
