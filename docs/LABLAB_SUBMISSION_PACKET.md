# RoomKey lablab submission packet

Status: `REPO_PACKET_READY_VIDEO_RECORDING_PENDING`

## Basic Information

### Project Title

RoomKey ScopeGate — Disclosure Gates for Band Agent Rooms

### Short Description

RoomKey gives Band agent rooms a disclosure gate: agents collaborate on regulated work, but sensitive context waits for a narrow human grant, then the run leaves a browser-checkable receipt.

### Long Description

RoomKey is a receipt-pinned prototype for authority-before-disclosure in Band agent rooms.

Agent rooms make multi-agent work useful. Regulated work makes disclosure expensive. The hard problem is not getting agents to collaborate; it is proving that sensitive context moved only after someone with authority narrowed the scope.

RoomKey adds a disclosure gate to the room. Agents can ask, summarize, review, and hand off work, but protected context stays blocked until a human grant exists for this case. In the supplier bank-change demo, agents coordinate on safe summaries, hashes, policy excerpts, and reviewer decisions while raw banking values stay out of shared Band history. The run then revokes access, checks that late replay stays blocked, and seals the evidence in a browser-checkable receipt.

The public demo page lets judges verify the proof path themselves: the browser checks the public bundle, receipt shape, receipt hashes, receipt-file equality, and proof flags for this prototype run. The project does not claim production security or independent Band-side security; it proves this bounded receipt-pinned run.

### Technology & Category Tags

Band Agent API, multi-agent collaboration, regulated workflows, agent governance, audit trail, authority-before-disclosure, enterprise AI, compliance, procurement, finance automation

## Cover Image and Presentation

### Cover Image

`media/lablab-cover-16x9.png`

- Format: PNG
- Size: 1920x1080
- Aspect: 16:9
- Status: ready locally; should be uploaded as the lablab cover image

### Video Presentation

Status: recording/upload still needed.

Script/shot list is ready at:

`docs/LABLAB_VIDEO_SCRIPT.md`

Recommended video length: 75–90 seconds, safely under the 5-minute lablab limit.

### Slide Presentation

`docs/lablab-roomkey-slide-deck.pdf`

- 6 slides
- PDF format
- 16:9 slide art source images in `media/slide-*.png`
- Status: ready locally; should be uploaded as the slide presentation

## App Hosting & Code Repository

### Public GitHub Repository

https://github.com/davfd/ScopeGateRoomKey

Public repository:

https://github.com/davfd/ScopeGateRoomKey

### Demo Application Platform

GitHub Pages static evidence console.

### Application URL

https://davfd.github.io/ScopeGateRoomKey/

Direct evidence console:

https://davfd.github.io/ScopeGateRoomKey/site/index.html

## What a Judge Can Verify

1. The page opens with the five-step run: Agent asks → Gate blocks → Human grants scope → Safe collaboration → Revoke + seal.
2. Browser badges verify the public bundle, receipt shape, and receipt hash equality.
3. Download cards provide the proof pack, use-case brief, attack matrix, receipt JSON, mutation receipt, evidence manifest, and submit seal.
4. Raw verifier lines stay collapsed for auditors.
5. The stricter local gate is `make submit-check`.

## Current Readiness Checklist

| Requirement | Status | Asset / answer |
|---|---:|---|
| Project Title | READY | RoomKey ScopeGate — Disclosure Gates for Band Agent Rooms |
| Short Description | READY | see above; <=255 chars |
| Long Description | READY | see above; >100 words |
| Technology & Category Tags | READY | see above |
| Cover Image | READY IN REPO | `media/lablab-cover-16x9.png` |
| Video Presentation | NEEDS RECORDING | script ready: `docs/LABLAB_VIDEO_SCRIPT.md` |
| Slide Presentation | READY IN REPO | `docs/lablab-roomkey-slide-deck.pdf` |
| Public GitHub Repository | READY LIVE | https://github.com/davfd/ScopeGateRoomKey |
| Demo Application Platform | READY LIVE | GitHub Pages |
| Application URL | READY LIVE | https://davfd.github.io/ScopeGateRoomKey/ |
| IBM Bob report | UNKNOWN / NEEDS EXPORT IF REQUIRED | not present in repo; export from lablab/IBM Bob if the hackathon requires it |

## Honest Boundary

This submission proves a receipt-pinned prototype run. It does not prove production security, independent Band-side security, exhaustive replay protection, or production-grade identity guarantees.
