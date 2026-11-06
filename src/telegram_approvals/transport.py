"""The transport interface the queue talks to."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol


class TelegramTransport(Protocol):
    """Minimal Bot API surface needed by the approval queue."""

    def send_message(self, chat_id: int, text: str, buttons: Sequence[tuple[str, str]]) -> int:
        """Send an HTML message with one inline button per ``(label, callback_data)``.

        Returns the id of the sent message.
        """

    def edit_message(self, chat_id: int, message_id: int, text: str) -> None:
        """Replace the HTML text of a message and drop its buttons."""

    def answer_callback(self, callback_query_id: str, text: str) -> None:
        """Answer a callback query with a short notice."""
