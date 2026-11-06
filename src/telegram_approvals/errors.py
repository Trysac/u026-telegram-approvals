"""Typed errors raised by telegram_approvals."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal[
    "malformed_callback",
    "unauthorized",
    "unknown_request",
    "expired",
    "already_decided",
    "too_many_pending",
    "text_too_long",
    "transport_failed",
    "invalid_config",
]

_MAX_MESSAGE_CHARS = 200


class ApprovalError(Exception):
    """Base error of the library.

    Attributes:
        code: Stable machine-readable error code.
        message: Human-readable description, at most 200 characters. It never contains the
            secret, a MAC or caller-supplied text.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        text = message[:_MAX_MESSAGE_CHARS]
        super().__init__(text)
        self.code: ErrorCode = code
        self.message: str = text

    def __repr__(self) -> str:
        return f"ApprovalError(code={self.code!r}, message={self.message!r})"
