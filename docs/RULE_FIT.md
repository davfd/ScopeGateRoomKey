| Rule / criterion | RoomKey evidence |
|---|---|
| 3+ agents collaborate through Band | `docs/AGENTS.md` and `make judge-proof` bind requester, reviewers, and auditor/gatekeeper to Band message IDs. |
| Band is the collaboration layer, not a wrapper | live receipt contains Band message IDs for @mention-style room posts, reviewer deposits, grant state, revocation, and seal. |
| Shared context / handoff / state | scoped releases expose only hash/count/key names; reviewer deposits and revocation change ScopeGate state. |
| official Band Agent API | the prototype posts through the Band room message API; the receipt records returned Band message IDs, status, and hashes for this run. |
| Application of Technology | authority-before-disclosure is implemented as a Band-room collaboration primitive. |
| Presentation | one-spear first-minute script, evidence console, and `make submit-check`. |
| Business Value | legal, finance, medical, procurement, and incident rooms can collaborate without spraying sensitive payloads into room history. |
| Originality | RoomKey makes authority-before-disclosure visible: block, grant, scoped release, revoke, seal. |
