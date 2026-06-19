# Agent trace

RoomKey records which agents participated in the supplier bank-change review and which Band messages witnessed their work. The important boundary is simple: agents can coordinate, but sensitive context only moves after a narrow human grant.

| Agent | Role | Band evidence | ScopeGate state transition |
|---|---|---|---|
| Intake Requester | asks for the review before authority exists | `2e100e92-32fd-42ee-adad-e2e3fba28085`, `c0c9ca23-969c-4e31-8f1f-396e97d575c5` | `NO_GRANT -> action.blocked` |
| ReviewerA | reviews inside the approved scope | `15393005-43f8-4ba6-a48a-59b0e15d548b` | `GRANT_SCOPED -> reviewer.deposit` |
| ReviewerB | reviews inside the approved scope | `911b069a-70fd-4936-8906-2969fabfeb4e` | `GRANT_SCOPED -> reviewer.deposit` |
| ReviewerC | reviews inside the approved scope and escalates the mismatch | `2974e3d4-019e-4af0-9c1d-f3312e22f668` | `GRANT_SCOPED -> reviewer.deposit` |
| ScopeGate Auditor/Gatekeeper | blocks, opens, revokes, and seals the run | `3a602d9e-2411-4fb4-944f-0fa094e6df71` plus receipt event IDs | `BLOCK -> GRANT_SCOPED -> REPLAY_BLOCKED -> REVOKED -> BLOCK -> SEALED` |

Run `make judge-proof` for the full machine-readable trace.
