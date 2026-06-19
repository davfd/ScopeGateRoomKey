# Evidence contract

The pinned live receipt remains `receipts/live-band-demo-20260618T185330Z.json`; changing it must fail `scripts/integrity_check.py` unless every pinned root hash is intentionally updated.

The public proof contract is therefore a two-file bundle:

1. `receipt.schema.json` validates the immutable live Band spear receipt: message IDs, events, blocked attempts, scoped releases, replay probe, reviewer deposits, revocation, post-revocation blocks, and no-payload scan fields.
2. `public-proof.schema.json` validates the public evidence bundle in `site/evidence.json`: named `agent_trace`, `seal_post_message_id`, proof booleans, concrete `use_case`, `attack_survival`, and downloadable proof links.

The CLI gates (`scripts/integrity_check.py` and `scripts/site_check.py`) perform full JSON Schema validation against both schema files. The browser evidence console performs a smaller front-door contract check, then binds the displayed receipt to the pinned payload hash and file-byte hash in `site/evidence.json`. A green console must show:

```text
browser_evidence_contract_check=PASS
browser_receipt_contract_check=PASS
browser_receipt_hash_check=PASS
browser_receipt_file_hash_check=PASS
browser_site_canonical_receipt_match=PASS
```
