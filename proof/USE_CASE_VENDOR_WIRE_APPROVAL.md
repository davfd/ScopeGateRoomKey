# Use case: vendor bank-change approval

A supplier asks finance to change payment instructions before a wire is released. The room needs fast multi-agent review, but the raw vendor banking payload should not be sprayed into shared Band history.

## Why agents use RoomKey

- Requester asks for the payment review.
- Evidence agent fetches invoice summary, vendor record, and policy excerpt.
- Risk agent checks mismatch signals and prepares a safe summary.
- ReviewerA/B/C deposit scoped allow/escalate decisions.
- Action agent prepares the next step only if ScopeGate sees the matching human grant.

## Why a human uses RoomKey

The finance lead can grant a narrow scope: case ID, allowed agents, allowed context keys, allowed action, expiry, and revocation. The human does not need to trust every prompt in the room. ScopeGate turns the human approval into a machine-checkable key.

## What the room sees

- case id: `vendor-wire-001`
- context key names
- hash/count summaries
- reviewer deposits
- receipt/seal proof

## What stays out of the room

- raw account/routing values
- protected sample payload values
- secret/canary values

Boundary: this proves the documented prototype run and local verifier gates, not production security or independent Band-side enforcement.
