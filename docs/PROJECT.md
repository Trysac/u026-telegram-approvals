# Project record

## Objective

Human approval queue for agent actions with HMAC-signed Telegram inline buttons, approver allow list, expiry and a bounded audit trail

## Scope

- In scope: the public API documented in [README.md](../README.md), typed and tested.
- Out of scope: anything that needs runtime dependencies or I/O without an accepted ADR.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 432372 / 76324 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.6695 |

## Factory run u026 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 3082 | 61665 | 0 | 4246 | 0.3118 |
| fix-1 | claude-sonnet-5-5 | no | 4 | 549 | 6800 | 25193 | 0.0250 |
| fix-2 | claude-sonnet-5-5 | no | 6 | 661 | 8591 | 43729 | 0.0325 |
| fix-3 | claude-sonnet-5-5 | no | 12 | 1796 | 10462 | 94856 | 0.0536 |
| fix-4 | claude-sonnet-5-5 | no | 6 | 874 | 7764 | 41811 | 0.0323 |
| audit | claude-sonnet-5-5 | no | 10 | 3107 | 38714 | 106376 | 0.1385 |
| docs | claude-haiku-5-5 | no | 113041 | 7672 | 0 | 0 | 0.0757 |

Total: $0.6695. Prices: Anthropic list prices.
