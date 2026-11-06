# telegram-approvals

[![PyPI version](https://img.shields.io/pypi/v/trysac-telegram-approvals)](https://pypi.org/project/trysac-telegram-approvals/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-telegram-approvals)](LICENSE)
[![CI](https://github.com/Trysac/u026-telegram-approvals/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u026-telegram-approvals/actions/workflows/ci.yml)

Human approval queue for agent actions with HMAC-signed Telegram inline buttons, approver allow list, expiry and a bounded audit trail

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-telegram-approvals
# or
uv add trysac-telegram-approvals
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import telegram_approvals

# normalize() trims surrounding whitespace and lower-cases the text.
print(telegram_approvals.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    telegram_approvals.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
