#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any
from urllib.parse import unquote

RECEIPT_NAME = 'live-band-demo-20260618T185330Z.json'
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def sha256_hex(text: str) -> str:
    return sha256(text.encode('utf-8')).hexdigest()


def sha_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def require_fields(obj: dict[str, Any], fields: list[str]) -> list[str]:
    return [field for field in fields if field not in obj]


def resolve_href(site_dir: Path, href: str) -> Path:
    clean = href.split('#', 1)[0].split('?', 1)[0]
    return (site_dir / unquote(clean)).resolve()


def validate_downloads(root: Path, site_dir: Path, evidence: dict[str, Any], evidence_path: Path) -> list[str]:
    failures: list[str] = []
    downloads = evidence.get('downloads')
    if not isinstance(downloads, list) or len(downloads) < 5:
        return ['downloads incomplete']
    for index, item in enumerate(downloads):
        if not isinstance(item, dict):
            failures.append(f'downloads[{index}] not object')
            continue
        href = item.get('href')
        label = item.get('label')
        if not isinstance(href, str) or not href:
            failures.append(f'downloads[{index}].href')
            continue
        if not isinstance(label, str) or not label:
            failures.append(f'downloads[{index}].label')
        target = resolve_href(site_dir, href)
        try:
            target.relative_to(root.resolve())
        except ValueError:
            failures.append(f'downloads[{index}] escapes repo')
            continue
        if not target.exists() or not target.is_file():
            failures.append(f'downloads[{index}] missing {href}')
            continue
        expected = item.get('sha256')
        if expected is not None:
            if not isinstance(expected, str) or not HEX64.match(expected):
                failures.append(f'downloads[{index}].sha256')
            elif sha_file(target) != expected:
                failures.append(f'downloads[{index}] hash mismatch {href}')
        elif item.get('self_verifying') is True and target == evidence_path.resolve():
            pass
        else:
            failures.append(f'downloads[{index}] missing sha256')
    return failures


def validate_evidence_contract(root: Path, evidence: dict[str, Any]) -> list[str]:
    site_dir = root / 'site'
    evidence_path = site_dir / 'evidence.json'
    failures: list[str] = []
    failures.extend(
        f'evidence missing {field}'
        for field in require_fields(
            evidence,
            ['winning_frame', 'canonical_receipt_sha256', 'live_receipt_file_sha256', 'seal_post_message_id', 'agent_trace', 'proof', 'use_case', 'attack_survival', 'downloads'],
        )
    )
    if failures:
        return failures

    if len(evidence.get('agent_trace', {})) < 3:
        failures.append('agent_trace < 3')
    proof = evidence.get('proof', {})
    if proof.get('agents_named') is not True or proof.get('agent_trace_present') is not True or proof.get('band_message_ids_present') is not True:
        failures.append('agent proof incomplete')
    if proof.get('late_replay_recovered') is not False:
        failures.append('late replay recovered')
    if proof.get('raw_secret_canary_posted') is not False:
        failures.append('raw canary posted')
    if proof.get('protected_payload_value_posted') is not False:
        failures.append('protected payload posted')
    use_case = evidence.get('use_case', {})
    if not isinstance(use_case, dict) or 'Vendor bank-change approval' not in use_case.get('title', ''):
        failures.append('use case incomplete')
    if len(evidence.get('attack_survival', [])) < 5:
        failures.append('attack survival incomplete')
    failures.extend(validate_downloads(root, site_dir, evidence, evidence_path))
    return failures


def validate_receipt_contract(receipt: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    failures.extend(
        f'receipt missing {field}'
        for field in require_fields(
            receipt,
            [
                'mode', 'case_id', 'grant', 'grant_id', 'receipt_sha256', 'band_message_ids',
                'live_gate_events', 'blocked_attempts', 'context_releases', 'late_participant_probes',
                'reviewer_deposits', 'revocations', 'post_revocation_blocks', 'band_secret_scan', 'policy_log_sha256',
            ],
        )
    )
    if failures:
        return failures

    grant = receipt.get('grant', {})
    failures.extend(
        f'grant missing {field}'
        for field in require_fields(grant, ['case_id', 'room_id', 'grant_id', 'human_approver', 'allowed_agents', 'allowed_context_keys', 'allowed_action_kinds'])
    )
    if failures:
        return failures

    if grant.get('case_id') != receipt.get('case_id'):
        failures.append('grant case mismatch')
    if grant.get('grant_id') != receipt.get('grant_id'):
        failures.append('grant id mismatch')
    if receipt.get('mode') != 'live_band_spear':
        failures.append('mode mismatch')
    if not isinstance(receipt.get('band_message_ids'), list) or len(receipt.get('band_message_ids', [])) < 1:
        failures.append('missing band ids')
    events = receipt.get('live_gate_events', [])
    if not isinstance(events, list) or not all(e.get('band_message_id') and e.get('band_ok') is True and e.get('band_content_sha256') for e in events if isinstance(e, dict)) or any(not isinstance(e, dict) for e in events):
        failures.append('bad live events')
    if len(receipt.get('reviewer_deposits', [])) != 3:
        failures.append('expected 3 reviewer deposits')
    scan = receipt.get('band_secret_scan', {})
    if scan.get('raw_secret_canary_posted') is not False:
        failures.append('raw canary posted')
    if scan.get('protected_payload_value_posted') is not False:
        failures.append('protected payload posted')
    if any(probe.get('recovered') for probe in receipt.get('late_participant_probes', []) if isinstance(probe, dict)):
        failures.append('late replay recovered')
    return failures


def run(root: Path) -> tuple[int, list[str]]:
    site_dir = root / 'site'
    evidence_path = site_dir / 'evidence.json'
    evidence_text = evidence_path.read_text(encoding='utf-8')
    site_receipt_text = (site_dir / 'receipts' / RECEIPT_NAME).read_text(encoding='utf-8')
    canonical_receipt_text = (root / 'receipts' / RECEIPT_NAME).read_text(encoding='utf-8')

    evidence = json.loads(evidence_text)
    receipt = json.loads(site_receipt_text)
    lines: list[str] = []

    lines.append('winning_frame=' + str(evidence.get('winning_frame')))
    lines.append('canonical_receipt_sha256=' + str(evidence.get('canonical_receipt_sha256')))
    lines.append('live_receipt_file_sha256=' + str(evidence.get('live_receipt_file_sha256')))
    lines.append('seal_post_message_id=' + str(evidence.get('seal_post_message_id')))
    lines.append('agents=' + str(len(evidence.get('agent_trace', {}))))
    proof = evidence.get('proof', {})
    lines.append('late_replay_recovered=' + str(proof.get('late_replay_recovered')).lower())
    lines.append('raw_secret_canary_posted=' + str(proof.get('raw_secret_canary_posted')).lower())
    lines.append('protected_payload_value_posted=' + str(proof.get('protected_payload_value_posted')).lower())

    evidence_failures = validate_evidence_contract(root, evidence)
    if evidence_failures:
        lines.append('browser_evidence_contract_check=FAIL ' + '; '.join(evidence_failures))
    else:
        lines.append('browser_evidence_contract_check=PASS')

    receipt_failures = validate_receipt_contract(receipt)
    if receipt_failures:
        lines.append('browser_receipt_contract_check=FAIL ' + '; '.join(receipt_failures))
    else:
        lines.append('browser_receipt_contract_check=PASS')

    copy = json.loads(json.dumps(receipt))
    expected = copy.pop('receipt_sha256', None)
    actual = sha256_hex(canonical(copy))
    site_file_hash = sha256_hex(site_receipt_text)
    canonical_file_hash = sha256_hex(canonical_receipt_text)
    receipt_copies_match = site_receipt_text == canonical_receipt_text
    payload_hash_ok = expected == actual and evidence.get('canonical_receipt_sha256') == actual
    file_hash_ok = receipt_copies_match and evidence.get('live_receipt_file_sha256') == site_file_hash and evidence.get('live_receipt_file_sha256') == canonical_file_hash

    lines.append('browser_receipt_hash_check=' + ('PASS' if payload_hash_ok else 'FAIL'))
    lines.append('browser_receipt_hash=' + actual)
    lines.append('browser_receipt_file_hash_check=' + ('PASS' if file_hash_ok else 'FAIL'))
    lines.append('browser_receipt_file_hash=' + site_file_hash)
    lines.append('browser_canonical_receipt_file_hash=' + canonical_file_hash)
    lines.append('browser_site_canonical_receipt_match=' + ('PASS' if receipt_copies_match else 'FAIL'))

    ok = not evidence_failures and not receipt_failures and payload_hash_ok and file_hash_ok
    return (0 if ok else 1), lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Deterministically replay the browser receipt hash/equality contract.')
    parser.add_argument('--root', default='.', help='RoomKey repository root to verify')
    args = parser.parse_args(argv)
    try:
        code, lines = run(Path(args.root).resolve())
    except Exception as exc:  # noqa: BLE001 - CLI should return a stable FAIL marker, not traceback, for receipt gates.
        print('browser_verifier_contract_check=ERROR ' + str(exc))
        return 2
    print('\n'.join(lines))
    print('browser_verifier_contract_check=' + ('PASS' if code == 0 else 'FAIL'))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
