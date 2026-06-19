# RoomKey ScopeGate

**RoomKey is a receipt-pinned prototype for authority-before-disclosure in Band agent rooms.**

Agent rooms make multi-agent work useful. Regulated work makes disclosure expensive. The hard problem is not getting agents to collaborate. It is proving that sensitive context moved only after someone with authority narrowed the scope.

RoomKey adds a disclosure gate to the room. Agents can ask, summarize, review, and hand off work, but protected context stays blocked until a human grant exists for this case. When the run ends, RoomKey leaves a browser-checkable receipt: what was blocked, what was approved, what was revoked, and what protected values did not appear in shared Band history in this run.

## Try it

- Live evidence console: https://davfd.github.io/ScopeGateRoomKey/
- Public repo: https://github.com/davfd/ScopeGateRoomKey
- Proof pack: [`proof/ROOMKEY_PROOF_PACK.md`](proof/ROOMKEY_PROOF_PACK.md)
- Canonical receipt: [`receipts/live-band-demo-20260618T185330Z.json`](receipts/live-band-demo-20260618T185330Z.json)
- Lablab submission packet: [`docs/LABLAB_SUBMISSION_PACKET.md`](docs/LABLAB_SUBMISSION_PACKET.md)
- Slide deck PDF: [`docs/lablab-roomkey-slide-deck.pdf`](docs/lablab-roomkey-slide-deck.pdf)
- Cover image: [`media/lablab-cover-16x9.png`](media/lablab-cover-16x9.png)

## The demo in one paragraph

A supplier asks finance to change payment instructions before a wire goes out. A requester agent, evidence agent, risk agent, reviewers, and an action agent need to coordinate in a Band room. RoomKey lets them work without dumping raw banking details into shared room history. First the gate blocks the request. Then a human approves a narrow scope for this case. Agents review safe summaries, hashes, and policy excerpts. The operator revokes access. Late replay fails. The run is sealed with a receipt.

**Key insight:** a room is not a permission boundary. RoomKey makes disclosure its own event: blocked before authority, narrowed by a human grant, revoked after use, and sealed with a receipt.

## If you only have 90 seconds

1. Open the live console: https://davfd.github.io/ScopeGateRoomKey/
2. Read the first screen. It should answer what this is and why a regulated team would care.
3. Scroll to **What can you verify yourself?** The three green cards are live browser checks, not screenshots.
4. Download the proof pack if you want the short proof path.
5. Download the receipt JSON if you want the raw proof root.

## Audit it yourself

You can audit this at three depths.

### 1. Browser check

Open the live page. The browser checks the public files every time it loads. The cards mean:

- **Public bundle is intact**: the evidence file has the use case, agents, attacks, downloads, and seal ID.
- **Receipt has the right shape**: the receipt includes Band message IDs, gate events, reviewer deposits, revocation, and secret-scan fields.
- **Receipt was not swapped**: the site receipt matches the canonical receipt and the pinned hash.

If a proof file drifts, the green cards should turn red.

### 2. Local submit check

Clone the repo and run the stricter gate:

```bash
git clone https://github.com/davfd/ScopeGateRoomKey.git
cd ScopeGateRoomKey
python -m pip install -e . pytest
make submit-check
# if make is unavailable:
python scripts/submit_check.py
```

That runs schema checks, integrity checks, banned-copy checks, the browser verifier harness, and the regression tests.

### 3. Decode the raw verifier lines

The raw lines are an auditor appendix. Here is what they mean.

| Raw line | Plain English |
|---|---|
| `winning_frame=Give every agent room a disclosure gate.` | The page thesis. Useful for orientation, not a proof by itself. |
| `canonical_receipt_sha256=b737...` | The fingerprint of the receipt content the page claims as canonical. |
| `browser_receipt_hash=b737...` | What your browser computed from the receipt. It should match the canonical hash. |
| `live_receipt_file_sha256=f6d2...` | The fingerprint of the receipt file shipped with the site. |
| `browser_receipt_file_hash=f6d2...` | What your browser computed from that file. It should match the shipped-file hash. |
| `browser_site_canonical_receipt_match=PASS` | The site copy and canonical copy of the receipt are byte-identical. |
| `raw_secret_canary_posted=false` | The secret canary was not found in shared Band room history in this run. |
| `protected_payload_value_posted=false` | The protected payload value was not posted in shared Band room history in this run. |
| `late_replay_recovered=false` | A late replay attempt did not recover protected context. |
| `browser_*_check=PASS` | The browser checked evidence structure, receipt structure, receipt hash, receipt file hash, and site/canonical receipt equality. |

The short version: your browser checks that the receipt is the same receipt, the public proof bundle still matches, protected values were not posted in this run, and replay stayed blocked. You do not have to trust the page copy.

## Demo video script

If you are judging this from a video, the clean version is under 90 seconds.

- **0-15 seconds**: Agent rooms need shared context. In regulated work, shared context can become a leak.
- **15-35 seconds**: Show the supplier bank-change request. RoomKey blocks sensitive disclosure before approval.
- **35-55 seconds**: Show the human grant. Agents can now review safe summaries, hashes, and policy excerpts.
- **55-70 seconds**: Show revocation and late replay failing closed.
- **70-90 seconds**: Show the live verifier and downloadable receipts. The proof is not just a claim on the page.

## What survived in this run

- Pre-grant access stayed blocked.
- Scoped release exposed safe summaries/hashes, not raw protected values.
- Three reviewer deposits were recorded.
- Revocation closed the key.
- Late replay stayed blocked.
- Receipt divergence, schema corruption, forged-looking IDs, stale proof metadata, and overclaim copy were turned into checks or regression tests.

## How it maps to the Band challenge

| Criterion | RoomKey evidence |
|---|---|
| 3+ agents collaborate through Band | Requester, evidence, risk, reviewer/action, and audit/gate roles are bound to Band message IDs in the receipt. |
| Band is the collaboration layer | The receipt records Band message IDs for room posts, reviewer deposits, grant state, revocation, and seal. |
| Shared context / handoff / state | Agents see safe labels, hashes, summaries, decisions, and gate state before raw context can move. |
| Agent API use | The prototype posts through the Band room message API and records returned message IDs/status for this run. |
| Business value | Finance, healthcare, legal, compliance, procurement, and incident rooms can collaborate without spraying sensitive payloads into shared history. |
| Originality | RoomKey turns authority-before-disclosure into a visible room primitive: block, grant, scoped release, revoke, seal. |

## Downloadable proof

- [`proof/ROOMKEY_PROOF_PACK.md`](proof/ROOMKEY_PROOF_PACK.md): short judge-readable proof path.
- [`proof/ATTACK_MATRIX.json`](proof/ATTACK_MATRIX.json): machine-readable attack survival matrix.
- [`proof/USE_CASE_VENDOR_WIRE_APPROVAL.md`](proof/USE_CASE_VENDOR_WIRE_APPROVAL.md): concrete operator use case.
- [`proof/TEXT_INJECTION_MUTATION_RECEIPT.md`](proof/TEXT_INJECTION_MUTATION_RECEIPT.md): prompt-like text stayed inert.
- [`receipts/live-band-demo-20260618T185330Z.json`](receipts/live-band-demo-20260618T185330Z.json): canonical receipt.
- [`site/evidence.json`](site/evidence.json): public evidence manifest.
- [`docs/PUBLIC_SUBMIT_SEAL.md`](docs/PUBLIC_SUBMIT_SEAL.md): deploy/readback seal.

## Claim boundary

Say: RoomKey proves a receipt-pinned prototype run of authority-before-disclosure in a Band room. The receipt and integrity gates show protected payload values were not posted to Band in this run.

Do not say: this proves production security, independent Band-side security, exhaustive replay protection, or production identity guarantees.
