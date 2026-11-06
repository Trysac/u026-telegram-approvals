# Security

This document is the threat model of `trysac-telegram-approvals`. The same summary is in the
module docstring of `telegram_approvals`.

## Threat model

The library gates agent actions behind a human decision made with Telegram inline buttons. The
attacker can see and replay button data, press buttons from any account in the chat, and
send late or repeated callbacks.

### Defended

Each item has a dedicated test.

| Threat | Defence |
|---|---|
| Forged or tampered callback data | Data is `<v>:<id>:<mac>` where `mac` is the base64url (no padding) of the first 18 bytes of HMAC-SHA256 over `<v>:<id>` (RFC 2104 section 5 truncation), compared with `hmac.compare_digest`. A flipped verb, a changed MAC character or a swapped id fail with `unauthorized`. |
| Presses by non-approvers | The presser (`callback_query.from.id`) must be in `approver_ids`. The chat is never used for authorization, so group members cannot approve. |
| Double decisions | Terminal states are never rewritten; a second press raises `already_decided`. Decisions run under a lock. |
| Decisions after expiry | A press at or after `expires_at` expires the request and raises `expired`; an `EXPIRED` request stays expired. |

Check order in `handle_callback`: length and grammar, MAC, approver, lookup, terminal state,
expiry, decision. A bad MAC and a non-approver both answer `Not allowed` with the same error, so
the existence of an id is not revealed.

### Not defended

* A stolen bot token (the attacker can talk to Telegram as the bot).
* A compromised approver account.
* Anyone who holds the HMAC secret.
* Restarts: all state is in memory, so pending requests are lost.

### Out of scope

A Bot API client, webhooks, persistence and quorum rules.

## Limits and data handling

* `action` is limited to 200 and `summary` to 3000 UTF-16 code units (`text_too_long`).
* Callback data longer than 63 bytes is rejected as `malformed_callback`.
* At most `max_requests` requests are stored (oldest decided one is evicted, else
  `too_many_pending`); the audit trail keeps at most `max_audit_entries` entries.
* Errors, events and log records carry ids and codes only. They never contain the summary, the
  action, the secret or a MAC, and error messages are at most 200 characters.
* Keep the secret at 32 or more random bytes and out of source control.
