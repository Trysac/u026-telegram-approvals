"""Human approval queue for agent actions over Telegram inline buttons.

An agent that wants to post, pay or send on a user's behalf calls
:meth:`ApprovalQueue.request`; the queue sends a message with signed Approve and Reject buttons
through a :class:`TelegramTransport` and waits for :meth:`ApprovalQueue.handle_callback`.

Threat model
------------
Defended (each has a dedicated test):

* Forged or tampered callback data: every button carries a truncated HMAC-SHA256 tag over the
  verb and the request id, compared in constant time.
* Presses by non-approvers: the *presser* (``callback_query.from.id``) is checked against an
  allow list, never the chat, so group members cannot approve.
* Double decisions: terminal states are never rewritten and the decision is made under a lock.
* Decisions after expiry: a press at or after ``expires_at`` expires the request instead.

Not defended: a stolen bot token, a compromised approver account, anyone who holds the HMAC
secret, and restarts (all state lives in memory only).

Out of scope: a Bot API client, webhooks, persistence and quorum rules.
"""

from __future__ import annotations

import logging

from .approval_queue import ApprovalQueue
from .errors import ApprovalError, ErrorCode
from .models import ApprovalEvent, ApprovalRequest, ApprovalState, AuditEntry, EventKind
from .transport import TelegramTransport

__all__ = [
    "ApprovalError",
    "ApprovalEvent",
    "ApprovalQueue",
    "ApprovalRequest",
    "ApprovalState",
    "AuditEntry",
    "ErrorCode",
    "EventKind",
    "TelegramTransport",
    "__version__",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
