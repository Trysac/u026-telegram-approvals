"""Offline test double for :class:`telegram_approvals.TelegramTransport`."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class SentMessage:
    """A recorded ``send_message`` call."""

    chat_id: int
    text: str
    buttons: list[tuple[str, str]]
    message_id: int


@dataclass(frozen=True)
class EditedMessage:
    """A recorded ``edit_message`` call."""

    chat_id: int
    message_id: int
    text: str


@dataclass(frozen=True)
class AnsweredCallback:
    """A recorded ``answer_callback`` call."""

    callback_query_id: str
    text: str


class FakeTransport:
    """Records every call and can be told to fail.

    Calls are recorded before an error is raised, so failed attempts are visible too. Set
    ``send_error``, ``edit_error`` or ``answer_error`` to make the matching method raise.
    """

    def __init__(self, first_message_id: int = 1) -> None:
        self.sent: list[SentMessage] = []
        self.edits: list[EditedMessage] = []
        self.answers: list[AnsweredCallback] = []
        self.send_error: Exception | None = None
        self.edit_error: Exception | None = None
        self.answer_error: Exception | None = None
        self._next_id = first_message_id

    def send_message(self, chat_id: int, text: str, buttons: Sequence[tuple[str, str]]) -> int:
        """Record the message and return a sequential message id."""
        message_id = self._next_id
        self._next_id += 1
        self.sent.append(SentMessage(chat_id, text, list(buttons), message_id))
        if self.send_error is not None:
            raise self.send_error
        return message_id

    def edit_message(self, chat_id: int, message_id: int, text: str) -> None:
        """Record the edit."""
        self.edits.append(EditedMessage(chat_id, message_id, text))
        if self.edit_error is not None:
            raise self.edit_error

    def answer_callback(self, callback_query_id: str, text: str) -> None:
        """Record the callback answer."""
        self.answers.append(AnsweredCallback(callback_query_id, text))
        if self.answer_error is not None:
            raise self.answer_error
