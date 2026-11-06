# Authorize the presser and sign callback data with a truncated HMAC

Status: accepted (generated, pending human review)

## Context

Telegram inline button callbacks can be forged or replayed, and anyone in a group chat can press a button. Callback data is limited to 64 bytes, which rules out long signatures or stored server-side tokens that survive nothing. The library must be testable offline and must not depend on a Bot API client.

## Decision

Callback data is '<verb>:<id>:<mac>' with mac the base64url (no padding) of the first 18 bytes of HMAC-SHA256(secret, '<verb>:<id>'), compared in constant time, which keeps a 36-character id within 63 bytes. Authorization uses the presser id from the callback query against an allow list, never the chat. State is held in memory behind a lock, with a fixed check order that answers a bad MAC and a non-approver identically. Telegram access sits behind a three-method Protocol with a FakeTransport for tests. Request and audit storage are bounded, and expired requests count as decided for eviction.

## Consequences

A forged, flipped or replayed button is rejected without revealing whether an id exists, and group members cannot approve. An 18-byte tag gives 144 bits of forgery resistance, which is adequate for this use. State is lost on restart and a stolen bot token or secret defeats the scheme; both are documented as not defended. Holding the lock across transport calls makes decisions strictly serial at the cost of throughput.
