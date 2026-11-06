"""Behavior tests for the public API of telegram_approvals."""

from __future__ import annotations

import pytest

import telegram_approvals


def test_normalize_trims_and_lowercases() -> None:
    assert telegram_approvals.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        telegram_approvals.normalize(value)


def test_version_is_semver() -> None:
    parts = telegram_approvals.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
