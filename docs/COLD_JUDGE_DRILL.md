# Cold-judge drill result

Status: `PASS_COLD_JUDGE`
Timestamp: `2026-06-18T20:48Z`
Reviewer mode: fresh hackathon judge, no prior context, inspecting only README/site/docs.

## Answers captured

1. **Problem:** regulated multi-agent/Band rooms need shared context without spraying sensitive payloads into room history; disclosure must be conditional on authority.
2. **Agents:** Intake Requester triggers the sensitive-context path and pre-grant block; ReviewerA/B/C deposit scoped authority; ScopeGate Auditor/Gatekeeper enforces and verifies block -> grant -> replay block -> revocation -> post-revocation block -> receipt.
3. **ScopeGate enforces:** authority-before-disclosure.
4. **No-payload proof:** `protected_payload_value_posted=false`, `raw_secret_canary_posted=false`, `late_replay_recovered=false`, receipt hashes, Band seal post message ID.
5. **Use case:** vendor bank-change approval with requester, evidence, risk, reviewer, and action agents; human grants scope, ScopeGate enforces it.

Gaps: none from the cold-reader surface.
