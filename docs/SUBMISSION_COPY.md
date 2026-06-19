# Submission copy

## Title

RoomKey ScopeGate — Authority Before Disclosure for Band Agent Rooms

## Short description

RoomKey is a Band-native authority gate for regulated multi-agent rooms: agents collaborate through Band, but sensitive context is blocked until scoped authority exists, then revoked and verified with a Band-tied receipt.

## Long description

RoomKey answers the enterprise question inside a Band room: when should collaboration become disclosure?

In a live Band-room prototype run, RoomKey demonstrates specialized agents coordinating around sensitive vendor/legal-style context. Before authority, protected payload access is blocked. After scoped reviewer deposits, only safe metadata such as hashes, character counts, and context-key names are released. Late replay fails. Revocation removes authority in the harness. Post-revocation requests are blocked. A verifier-accepted receipt ties the chain to Band message IDs and the integrity gate checks that raw protected payload values were not posted in this run. This is not an independent security audit.

Band is the collaboration and witness surface. ScopeGate enforces authority-before-disclosure.

## Tags

Band Agent API, multi-agent collaboration, regulated workflows, audit trail, authority-before-disclosure, enterprise AI, governance
