#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
LIVE_RECEIPT = ROOT / 'receipts' / 'live-band-demo-20260618T185330Z.json'
SITE_RECEIPT = ROOT / 'site' / 'receipts' / 'live-band-demo-20260618T185330Z.json'
EVIDENCE = ROOT / 'site' / 'evidence.json'
SEAL_POST = ROOT / 'receipts' / 'live-band-demo-20260618T185330Z-seal-post.json'
SITE_SEAL_POST = ROOT / 'site' / 'receipts' / 'live-band-demo-20260618T185330Z-seal-post.json'
SCHEMAS = [ROOT / 'receipt.schema.json', ROOT / 'public-proof.schema.json']
EXPECTED_CANONICAL_RECEIPT_SHA256 = 'b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925'
EXPECTED_LIVE_RECEIPT_FILE_SHA256 = 'f6d2d843c7523212797a1237675a3592c477c754d0af905df767ea3005fa3b81'


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError as exc:
        raise ValueError(f'schema/json parse failed: {path.relative_to(ROOT)}: {exc}') from exc


def _canonical(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def _receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    payload = dict(receipt)
    payload.pop('receipt_sha256', None)
    return payload


def _sha256_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return sha256(text.encode('utf-8')).hexdigest()


def _validate_schema_files() -> list[str]:
    problems: list[str] = []
    for schema_path in SCHEMAS:
        try:
            schema = _load_json(schema_path)
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            problems.append(f'schema invalid: {schema_path.relative_to(ROOT)}: {exc}')
            continue
        for key in ('$schema', 'type', 'required', 'properties'):
            if key not in schema:
                problems.append(f'schema missing {key}: {schema_path.relative_to(ROOT)}')
        if schema.get('type') != 'object':
            problems.append(f'schema type must be object: {schema_path.relative_to(ROOT)}')
        if not isinstance(schema.get('required'), list) or not schema.get('required'):
            problems.append(f'schema required list missing/empty: {schema_path.relative_to(ROOT)}')
        if not isinstance(schema.get('properties'), dict) or not schema.get('properties'):
            problems.append(f'schema properties missing/empty: {schema_path.relative_to(ROOT)}')
    return problems


def _validate_instance(schema_path: Path, data_path: Path, data: Any) -> list[str]:
    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema)
    problems: list[str] = []
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.absolute_path)):
        location = '.'.join(str(part) for part in error.absolute_path) or '<root>'
        problems.append(
            f'schema validation failed: {data_path.relative_to(ROOT)} against '
            f'{schema_path.relative_to(ROOT)} at {location}: {error.message}'
        )
    return problems


def _validate_integrity() -> list[str]:
    problems: list[str] = []
    root_receipt = _load_json(LIVE_RECEIPT)
    site_receipt = _load_json(SITE_RECEIPT)
    evidence = _load_json(EVIDENCE)
    seal_post = _load_json(SEAL_POST)
    site_seal_post = _load_json(SITE_SEAL_POST)

    problems.extend(_validate_instance(ROOT / 'receipt.schema.json', LIVE_RECEIPT, root_receipt))
    problems.extend(_validate_instance(ROOT / 'receipt.schema.json', SITE_RECEIPT, site_receipt))
    problems.extend(_validate_instance(ROOT / 'public-proof.schema.json', EVIDENCE, evidence))

    if LIVE_RECEIPT.read_bytes() != SITE_RECEIPT.read_bytes():
        problems.append('site receipt copy differs from canonical receipt')

    grant = root_receipt.get('grant') or {}
    if grant.get('case_id') != root_receipt.get('case_id'):
        problems.append('grant.case_id does not match receipt case_id')
    if grant.get('grant_id') != root_receipt.get('grant_id'):
        problems.append('grant.grant_id does not match receipt grant_id')
    for index, release in enumerate(root_receipt.get('context_releases') or []):
        if release.get('case_id') != root_receipt.get('case_id'):
            problems.append(f'context release {index} case_id does not match receipt case_id')

    if SEAL_POST.read_bytes() != SITE_SEAL_POST.read_bytes():
        problems.append('site seal-post copy differs from canonical seal-post')

    canonical_hash = _sha256_text(_canonical(_receipt_payload(root_receipt)))
    receipt_field = root_receipt.get('receipt_sha256')
    evidence_hash = evidence.get('canonical_receipt_sha256')
    if receipt_field != canonical_hash:
        problems.append('canonical receipt hash field does not match recomputed receipt payload hash')
    if canonical_hash != EXPECTED_CANONICAL_RECEIPT_SHA256:
        problems.append('canonical receipt hash does not match pinned public root hash')
    if evidence_hash != canonical_hash:
        problems.append('site evidence canonical_receipt_sha256 does not match canonical receipt hash')

    root_file_hash = _sha256_file(LIVE_RECEIPT)
    if root_file_hash != EXPECTED_LIVE_RECEIPT_FILE_SHA256:
        problems.append('canonical receipt file bytes do not match pinned public file hash')
    if evidence.get('live_receipt_file_sha256') != root_file_hash:
        problems.append('site evidence live_receipt_file_sha256 does not match canonical receipt file bytes')
    if seal_post.get('receipt_file_sha256') != root_file_hash:
        problems.append('seal-post receipt_file_sha256 does not match canonical receipt file bytes')
    if seal_post.get('receipt_sha256') != canonical_hash:
        problems.append('seal-post receipt_sha256 does not match canonical receipt hash')
    if evidence.get('seal_post_message_id') != seal_post.get('seal_message_id'):
        problems.append('site evidence seal_post_message_id does not match seal-post receipt')

    event_ids = [event.get('band_message_id') for event in root_receipt.get('live_gate_events', [])]
    listed_ids = root_receipt.get('band_message_ids') or []
    if event_ids != listed_ids:
        problems.append('Band message id list does not exactly match live event message ids')
    if any(str(message_id).startswith('forged') or 'forged' in str(message_id) for message_id in listed_ids):
        problems.append('Band message id list contains forged-looking placeholder ids')

    return problems


def main() -> int:
    problems = _validate_schema_files() + _validate_integrity()
    if problems:
        print('integrity_check=FAIL')
        for problem in problems:
            print(problem)
        return 1
    print('integrity_check=PASS')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
