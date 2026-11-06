"""Immutable data types of the approval queue."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from .errors import ErrorCode

EventKind = Literal["requested", "decided", "expired", "callback_rejected"]


class ApprovalState(enum.Enum):
    """Lifecycle state of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ApprovalRequest:
    """One request for a human decision.

    ``action`` and ``summary`` are excluded from ``repr`` so they do not leak into logs.
    ``decided_at`` is also set when a request expires, to the moment it expired.
    """

    id: str
    action: str = field(repr=False)
    summary: str = field(repr=False)
    created_at: datetime
    expires_at: datetime
    state: ApprovalState
    decided_by: int | None
    decided_at: datetime | None
    message_id: int | None


@dataclass(frozen=True)
class AuditEntry:
    """One state transition of a request."""

    request_id: str
    actor_id: int | None
    old_state: ApprovalState
    new_state: ApprovalState
    at: datetime


@dataclass(frozen=True)
class ApprovalEvent:
    """Observability event; carries identifiers and codes only, never text or MACs."""

    kind: EventKind
    request_id: str | None
    state: ApprovalState | None = None
    actor_id: int | None = None
    code: ErrorCode | None = None
