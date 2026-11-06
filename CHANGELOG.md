# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `ApprovalQueue`: human approval queue for agent actions with HMAC-signed Telegram inline buttons, presser allow list, expiry, bounded request store and audit trail, a `TelegramTransport` protocol and an offline `FakeTransport`.
- Initial project structure from the factory utility template.
