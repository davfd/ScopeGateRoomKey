#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from hashlib import sha256
from pathlib import Path
from urllib.parse import unquote

from jsonschema import Draft202012Validator

REQUIRED_HTML = [
    'Console receipt run',
    'One screen. Commands, gate output, receipt PASS.',
    'protected values did not appear in shared Band history in this run',
    'Run console demo',
    'Jump to final PASS',
    'roomkey scopegate run --case VENDOR-WIRE-1849 --band live',
    'roomkey verify receipts/live-band-demo-20260618T185330Z.json',
    'pre-grant BLOCK',
    'human grant',
    'context releases',
    'reviewer deposits',
    'late replay BLOCKED',
    'receipt sealed',
    'id="console-lines"',
    'id="verification"',
    'Download proof pack',
    'Evidence bundle',
    'Receipt contract',
    'Receipt hash',
    'receipt-pinned prototype run',
    'does not prove production security',
]
REQUIRED_EVIDENCE = [
    'canonical_receipt_sha256', 'live_receipt_file_sha256', 'seal_post_message_id',
    'agent_trace', 'proof', 'use_case', 'attack_survival', 'downloads'
]
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def banned_phrases() -> list[str]:
    return [
        'Band privacy ' + 'firewall',
        'Band enforces ' + 'consent',
        'Band prevents ' + 'replay',
        'guaranteed consent ' + 'enforcement',
        'Guaranteed consent ' + 'enforcement',
        'production-' + 'secure',
        'production security ' + 'guarantee',
        'independent security audit ' + 'passed',
        'independent Band-side audit ' + 'passed',
        'OIDC-grade identity ' + 'assurance',
        'OAuth-grade identity ' + 'assurance',
        'public replacement ' + 'complete',
        'public push ' + 'complete',
        'security ' + 'verified',
        'verified ' + 'security',
        'proof of production ' + 'security',
        'cert' + 'ified',
        'tamper-' + 'proof',
        'compliance-' + 'ready',
        'guaranteed replay ' + 'protection',
        'Other Band projects make agents ' + 'collaborate',
        'not another workflow ' + 'room',
        'competitor ' + 'delta',
        'COMPETITOR_' + 'DELTA',
        'MUS' + 'TER',
        'Procure' + 'Guard',
        'Re' + 'course',
        'Sound' + 'check',
        'Quad' + 'ro',
    ]


def sha_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def resolve_href(site_dir: Path, href: str) -> Path:
    # These are static relative links, not web navigation. Strip anchors/query just in case.
    clean = href.split('#', 1)[0].split('?', 1)[0]
    return (site_dir / unquote(clean)).resolve()


def check_banned(paths: list[Path]) -> int:
    hits=[]
    for path in paths:
        candidates = path.rglob('*') if path.is_dir() else [path]
        for candidate in candidates:
            if not candidate.is_file() or any(part in {'.git','__pycache__','.pytest_cache'} for part in candidate.parts):
                continue
            try:
                text = candidate.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                continue
            for phrase in banned_phrases():
                if phrase in text:
                    hits.append(f'{candidate}:{phrase}')
    if hits:
        print('banned_claim_hits=')
        print('\n'.join(hits))
        return 1
    print('banned_claims=PASS')
    return 0


def validate_downloads(root: Path, site_dir: Path, evidence: dict, evidence_path: Path) -> list[str]:
    failures: list[str] = []
    downloads = evidence.get('downloads')
    if not isinstance(downloads, list) or len(downloads) < 5:
        return ['downloads>=5']
    for i, item in enumerate(downloads):
        if not isinstance(item, dict):
            failures.append(f'downloads[{i}] object')
            continue
        href = item.get('href')
        label = item.get('label')
        if not isinstance(href, str) or not href:
            failures.append(f'downloads[{i}].href')
            continue
        if not isinstance(label, str) or not label:
            failures.append(f'downloads[{i}].label')
        target = resolve_href(site_dir, href)
        try:
            target.relative_to(root.resolve())
        except ValueError:
            failures.append(f'downloads[{i}] escapes repo')
            continue
        if not target.exists() or not target.is_file():
            failures.append(f'downloads[{i}] missing {href}')
            continue
        expected = item.get('sha256')
        if expected is not None:
            if not isinstance(expected, str) or not HEX64.match(expected):
                failures.append(f'downloads[{i}].sha256')
            elif sha_file(target) != expected:
                failures.append(f'downloads[{i}] hash mismatch {href}')
        elif item.get('self_verifying') is True and target == evidence_path.resolve():
            pass
        else:
            failures.append(f'downloads[{i}] missing sha256')
    return failures


def validate_download_manifest(root: Path) -> list[str]:
    manifest_path = root / 'proof' / 'download-manifest.json'
    if not manifest_path.exists():
        return ['proof/download-manifest.json missing']
    failures: list[str] = []
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    files = manifest.get('files')
    if not isinstance(files, list) or len(files) < 5:
        return ['download-manifest files>=5']
    for i, item in enumerate(files):
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            failures.append(f'manifest.files[{i}].path')
            continue
        target = (root / item['path']).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            failures.append(f'manifest.files[{i}] escapes repo')
            continue
        if not target.exists() or not target.is_file():
            failures.append(f'manifest.files[{i}] missing {item["path"]}')
            continue
        expected = item.get('sha256')
        if expected is not None:
            if not isinstance(expected, str) or not HEX64.match(expected):
                failures.append(f'manifest.files[{i}].sha256')
            elif sha_file(target) != expected:
                failures.append(f'manifest.files[{i}] hash mismatch {item["path"]}')
        elif item.get('self_verifying') is True and item['path'] == 'site/evidence.json':
            pass
        else:
            failures.append(f'manifest.files[{i}] missing sha256')
    return failures


def visible_short_hash(path: Path) -> str:
    digest = sha_file(path)
    return f'{digest[:8]}…{digest[-6:]}'


def validate_visible_artifact_meta(root: Path, html: str) -> list[str]:
    failures: list[str] = []
    for rel in [
        'proof/ROOMKEY_PROOF_PACK.md',
        'proof/ATTACK_MATRIX.json',
        'proof/USE_CASE_VENDOR_WIRE_APPROVAL.md',
        'receipts/live-band-demo-20260618T185330Z.json',
        'proof/TEXT_INJECTION_MUTATION_RECEIPT.md',
        'site/evidence.json',
        'docs/PUBLIC_SUBMIT_SEAL.md',
    ]:
        target = root / rel
        if not target.exists():
            failures.append(f'visible meta missing target {rel}')
            continue
        short = visible_short_hash(target)
        if short not in html:
            failures.append(f'visible hash snippet missing/stale for {rel}: {short}')
    return failures


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[1] == '--banned-claims':
        return check_banned([Path(arg) for arg in argv[2:]])
    if len(argv) != 3:
        print('usage: site_check.py site/index.html site/evidence.json', file=sys.stderr)
        print('   or: site_check.py --banned-claims <paths...>', file=sys.stderr)
        return 2
    html_path = Path(argv[1])
    evidence_path = Path(argv[2])
    root = html_path.parent.parent
    site_dir = html_path.parent
    html = html_path.read_text(encoding='utf-8')
    evidence_text = evidence_path.read_text(encoding='utf-8')
    evidence = json.loads(evidence_text)
    missing_html = [needle for needle in REQUIRED_HTML if needle not in html]
    missing_evidence = [key for key in REQUIRED_EVIDENCE if key not in evidence]
    banned_hits = [needle for needle in banned_phrases() if needle in html or needle in evidence_text]
    proof = evidence.get('proof', {})
    if proof.get('late_replay_recovered') is not False:
        missing_evidence.append('proof.late_replay_recovered=false')
    if proof.get('raw_secret_canary_posted') is not False:
        missing_evidence.append('proof.raw_secret_canary_posted=false')
    if proof.get('protected_payload_value_posted') is not False:
        missing_evidence.append('proof.protected_payload_value_posted=false')
    if len(evidence.get('agent_trace', {})) < 3:
        missing_evidence.append('agent_trace>=3')
    if not isinstance(evidence.get('use_case'), dict) or 'Vendor bank-change approval' not in evidence.get('use_case', {}).get('title', ''):
        missing_evidence.append('use_case.vendor_bank_change')
    if len(evidence.get('attack_survival', [])) < 5:
        missing_evidence.append('attack_survival>=5')
    missing_evidence.extend(validate_downloads(root, site_dir, evidence, evidence_path))
    missing_evidence.extend(validate_download_manifest(root))
    missing_evidence.extend(validate_visible_artifact_meta(root, html))

    receipt_copy = site_dir / 'receipts' / 'live-band-demo-20260618T185330Z.json'
    root_receipt_path = root / 'receipts' / 'live-band-demo-20260618T185330Z.json'
    if not receipt_copy.exists():
        missing_evidence.append('site receipt copy missing')
    else:
        receipt = json.loads(receipt_copy.read_text(encoding='utf-8'))
        receipt_schema = root / 'receipt.schema.json'
        if receipt_schema.exists():
            schema = json.loads(receipt_schema.read_text(encoding='utf-8'))
            errors = sorted(Draft202012Validator(schema).iter_errors(receipt), key=lambda item: list(item.absolute_path))
            if errors:
                missing_evidence.append(f'receipt schema validation failed: {errors[0].message}')
        else:
            missing_evidence.append('receipt.schema.json')
        if root_receipt_path.exists() and receipt_copy.read_bytes() != root_receipt_path.read_bytes():
            missing_evidence.append('site receipt copy differs from canonical receipt')
        receipt_hash_payload = dict(receipt)
        expected_receipt_hash = receipt_hash_payload.pop('receipt_sha256', None)
        actual_receipt_hash = sha256(json.dumps(receipt_hash_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()
        if expected_receipt_hash != actual_receipt_hash:
            missing_evidence.append('canonical receipt hash mismatch')
        if evidence.get('canonical_receipt_sha256') != actual_receipt_hash:
            missing_evidence.append('evidence canonical receipt hash mismatch')
        receipt_file_hash = sha_file(receipt_copy)
        root_file_hash = sha_file(root_receipt_path) if root_receipt_path.exists() else None
        if evidence.get('live_receipt_file_sha256') != receipt_file_hash or evidence.get('live_receipt_file_sha256') != root_file_hash:
            missing_evidence.append('evidence live receipt file hash mismatch')
        for key in ['mode','receipt_sha256','band_message_ids','live_gate_events','blocked_attempts','context_releases','late_participant_probes','reviewer_deposits','revocations','post_revocation_blocks','band_secret_scan','policy_log_sha256']:
            if key not in receipt:
                missing_evidence.append(f'receipt.{key}')
        if receipt.get('mode') != 'live_band_spear':
            missing_evidence.append('receipt.mode=live_band_spear')
        if len(receipt.get('reviewer_deposits', [])) != 3:
            missing_evidence.append('receipt.reviewer_deposits=3')
        scan = receipt.get('band_secret_scan', {})
        if scan.get('raw_secret_canary_posted') is not False:
            missing_evidence.append('receipt.raw_secret_canary_posted=false')
        if scan.get('protected_payload_value_posted') is not False:
            missing_evidence.append('receipt.protected_payload_value_posted=false')
    public_schema = root / 'public-proof.schema.json'
    if not public_schema.exists():
        missing_evidence.append('public-proof.schema.json')
    else:
        try:
            schema = json.loads(public_schema.read_text(encoding='utf-8'))
            if not all(key in schema for key in ['$schema', 'type', 'required', 'properties']):
                missing_evidence.append('public-proof.schema.json valid contract')
            public_errors = sorted(Draft202012Validator(schema).iter_errors(evidence), key=lambda item: list(item.absolute_path))
            if public_errors:
                missing_evidence.append(f'public proof schema validation failed: {public_errors[0].message}')
        except json.JSONDecodeError:
            missing_evidence.append('public-proof.schema.json valid JSON')
    if missing_html or missing_evidence or banned_hits:
        print({'missing_html': missing_html, 'missing_evidence': missing_evidence, 'banned_hits': banned_hits})
        return 1
    print('site_check=PASS')
    return 0

if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
