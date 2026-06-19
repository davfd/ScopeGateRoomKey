from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def test_public_package_required_files_exist():
    required = [
        'Makefile', 'README.md', 'LICENSE', 'pyproject.toml', 'receipt.schema.json', 'public-proof.schema.json',
        '.github/workflows/ci.yml',
        'docs/AGENTS.md', 'docs/RULE_FIT.md', 'docs/EVIDENCE.md',
        'docs/CLAIMS_BOUNDARY.md', 'proof/ROOMKEY_PROOF_PACK.md', 'proof/ATTACK_MATRIX.json',
        'proof/USE_CASE_VENDOR_WIRE_APPROVAL.md', 'proof/download-manifest.json',
        'docs/SUBMISSION_COPY.md', 'docs/FIRST_MINUTE_SCRIPT.md',
        'docs/PUBLIC_SUBMIT_SEAL.md', 'docs/COLD_JUDGE_DRILL.md', 'docs/EVIDENCE_CONTRACT.md',
        'docs/LABLAB_SUBMISSION_PACKET.md', 'docs/LABLAB_VIDEO_SCRIPT.md', 'docs/lablab-roomkey-slide-deck.pdf',
        'media/lablab-cover-16x9.png',
        'scripts/judge_proof.py', 'scripts/secret_scan.py', 'scripts/integrity_check.py', 'scripts/site_check.py',
        'scripts/submit_check.py', 'scripts/browser_verifier_contract_check.py', 'scripts/receipt_timeline.py',
        'scripts/build_cli_transcript.py',
        'site/index.html', 'site/evidence.json', 'site/verifier.js', 'site/cli-transcript.txt', 'site/receipts/live-band-demo-20260618T185330Z.json',
        'receipts/live-band-demo-20260618T185330Z.json',
        'receipts/live-band-demo-20260618T185330Z-seal-post.json',
    ]
    missing = [path for path in required if not (ROOT / path).exists()]
    assert not missing

def test_judge_proof_prints_agent_trace_and_negative_proof():
    receipt = ROOT / 'receipts' / 'live-band-demo-20260618T185330Z.json'
    proc = subprocess.run(
        [sys.executable, str(ROOT / 'scripts' / 'judge_proof.py'), str(receipt)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    out = proc.stdout
    for needle in [
        'PASS_ROOMKEY_PROOF', 'agents_named=true', 'agent_trace_present=true',
        'band_message_ids_present=true', 'naive_path_blocked=true',
        'late_replay_recovered=false', 'reviewer_deposits=3',
        'post_revocation_block=true', 'raw_secret_canary_posted=false',
        'protected_payload_value_posted=false', 'seal_post_message_id=3a602d9e-2411-4fb4-944f-0fa094e6df71',
        'agent_trace.requester', 'agent_trace.reviewer_a', 'agent_trace.auditor_gatekeeper',
    ]:
        assert needle in out


def test_receipt_timeline_cli_prints_real_workflow_from_receipt():
    receipt = ROOT / 'receipts' / 'live-band-demo-20260618T185330Z.json'
    proc = subprocess.run(
        [sys.executable, str(ROOT / 'scripts' / 'receipt_timeline.py'), str(receipt)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    out = proc.stdout
    for needle in [
        'PASS_RECEIPT_TIMELINE',
        'case_id=vendor-wire-001',
        'mode=live_band_spear',
        'band_messages=25',
        '03 pre-grant BLOCK action=send_wire_review reason=no scoped grant',
        '05 human grant GRANTED grant_id=grant_0204c5961d10',
        '10 context RELEASED key=policy_excerpt raw_posted=false',
        '11 late replay BLOCKED participant=Unapproved Auditor recovered=false',
        '14 reviewer DEPOSIT reviewer=ReviewerA verdict=ALLOW independent=true raw_posted=false',
        '21 review gate ADJUDICATED outcome=HUMAN_ESCALATE reviewers=3',
        '22 grant REVOKED grant_id=grant_0204c5961d10',
        '23 post-revocation BLOCK action=send_wire_review reason=grant revoked',
        '24 context BLOCKED key=policy_excerpt reason=grant revoked',
        '25 receipt SEALED receipt_sha256=b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925',
        'protected_payload_value_posted=false',
        'raw_secret_canary_posted=false',
        'late_replay_recovered=false',
    ]:
        assert needle in out


def test_cli_transcript_is_real_command_output_not_button_animation():
    transcript = (ROOT / 'site' / 'cli-transcript.txt').read_text(encoding='utf-8')
    html = (ROOT / 'site' / 'index.html').read_text(encoding='utf-8')
    verifier = (ROOT / 'site' / 'verifier.js').read_text(encoding='utf-8')

    for needle in [
        '$ python scripts/receipt_timeline.py receipts/live-band-demo-20260618T185330Z.json',
        'PASS_RECEIPT_TIMELINE',
        '03 pre-grant BLOCK action=send_wire_review reason=no scoped grant',
        '25 receipt SEALED receipt_sha256=b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925',
        '$ PYTHONPATH=src python -m roomkey.cli verify receipts/live-band-demo-20260618T185330Z.json',
        'PASS_DEMO_PROOF',
        '$ python scripts/judge_proof.py receipts/live-band-demo-20260618T185330Z.json',
        'PASS_ROOMKEY_PROOF',
        '$ python scripts/browser_verifier_contract_check.py --root .',
        'browser_receipt_hash_check=PASS',
        'browser_site_canonical_receipt_match=PASS',
    ]:
        assert needle in transcript

    assert 'Real CLI transcript' in html
    assert "fetchText('cli-transcript.txt')" in verifier
    assert 'Run console demo' not in html
    assert 'console-run' not in html

def test_site_evidence_is_machine_readable_and_matches_receipt():
    evidence = json.loads((ROOT / 'site' / 'evidence.json').read_text(encoding='utf-8'))
    assert evidence['canonical_receipt_sha256'] == 'b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925'
    assert evidence['seal_post_message_id'] == '3a602d9e-2411-4fb4-944f-0fa094e6df71'
    assert evidence['proof']['late_replay_recovered'] is False
    assert evidence['proof']['raw_secret_canary_posted'] is False
    assert evidence['proof']['protected_payload_value_posted'] is False
    assert len(evidence['agent_trace']) >= 3

def test_site_browser_verifier_wording_matches_console_surface():
    html = (ROOT / 'site' / 'index.html').read_text(encoding='utf-8')
    verifier = (ROOT / 'site' / 'verifier.js').read_text(encoding='utf-8')
    evidence_contract = (ROOT / 'docs' / 'EVIDENCE_CONTRACT.md').read_text(encoding='utf-8')

    assert 'Live Band receipt verified in ' + 'browser' not in html
    assert '<h3>Receipt ' + 'schema</h3>' not in html
    assert 'Real CLI transcript' in html
    assert 'No fake run button' in html
    assert 'site/cli-transcript.txt' in html
    assert 'id="console-lines"' in html
    assert 'Download proof pack' in html
    assert 'receipt-pinned prototype run' in html
    for removed in [
        'Run console demo', 'console-run', 'Actual backend workflow', 'Try the gate', 'The five moves', 'How it feels to use',
        'Where this fits', 'Attack resistance proven in this run', 'id="demo-transcript"',
        'id="workflow-stage-list"',
    ]:
        assert removed not in html

    assert "fetchText('../receipts/live-band-demo-20260618T185330Z.json')" in verifier
    assert 'loadCliTranscript' in verifier
    assert "fetchText('cli-transcript.txt')" in verifier
    assert 'console-lines' in verifier
    assert 'evidence.canonical_receipt_sha256 === actual' in verifier
    assert 'evidence.live_receipt_file_sha256 === siteFileHash' in verifier
    assert 'evidence.live_receipt_file_sha256 === canonicalFileHash' in verifier
    assert 'browser_receipt_contract_check=PASS' in verifier
    assert 'browser_receipt_file_hash_check=' in verifier
    assert 'browser_site_canonical_receipt_match=' in verifier
    assert 'browser_' + 'schema_check' not in verifier
    assert 'SKIP_LOCAL_' + 'FETCH_PATH' not in verifier

    assert 'browser_receipt_contract_check=PASS' in evidence_contract
    assert 'browser_receipt_file_hash_check=PASS' in evidence_contract
    assert 'browser_site_canonical_receipt_match=PASS' in evidence_contract


def test_browser_receipt_contract_harness_fails_on_divergent_site_receipt(tmp_path):
    harness = ROOT / 'scripts' / 'browser_verifier_contract_check.py'

    positive = subprocess.run(
        [sys.executable, str(harness), '--root', str(ROOT)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    assert 'browser_receipt_file_hash_check=PASS' in positive.stdout
    assert 'browser_site_canonical_receipt_match=PASS' in positive.stdout

    mutated_root = tmp_path / 'mutated-roomkey'
    shutil.copytree(ROOT, mutated_root, ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache', '*.pyc'))
    site_receipt_path = mutated_root / 'site' / 'receipts' / 'live-band-demo-20260618T185330Z.json'
    site_receipt = json.loads(site_receipt_path.read_text(encoding='utf-8'))
    site_receipt['case_id'] = site_receipt['case_id'] + '-tampered'
    site_receipt_path.write_text(json.dumps(site_receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False), encoding='utf-8')

    negative = subprocess.run(
        [sys.executable, str(harness), '--root', str(mutated_root)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert negative.returncode == 1
    assert 'browser_receipt_contract_check=FAIL' in negative.stdout
    assert 'browser_receipt_hash_check=FAIL' in negative.stdout
    assert 'browser_receipt_file_hash_check=FAIL' in negative.stdout
    assert 'browser_site_canonical_receipt_match=FAIL' in negative.stdout


def test_site_exposes_single_console_demo_not_crowded_brochure():
    html = (ROOT / 'site' / 'index.html').read_text(encoding='utf-8')
    verifier = (ROOT / 'site' / 'verifier.js').read_text(encoding='utf-8')

    for needle in [
        'Real CLI transcript',
        'No fake run button',
        'actual CLI commands and captured stdout',
        'site/cli-transcript.txt',
        'generated by scripts/build_cli_transcript.py',
        'id="console-lines"',
        'id="verification"',
    ]:
        assert needle in html

    for needle in [
        'loadCliTranscript',
        "fetchText('cli-transcript.txt')",
        'console-lines',
    ]:
        assert needle in verifier

    for removed in [
        'workflow-console', 'interactive-demo', 'story-card', 'attack-grid',
        'Play actual receipt run', 'Grant Scope', 'Run scoped review', 'Run console demo', 'console-run',
        'renderConsoleReceiptRun', 'initConsoleDemo',
    ]:
        assert removed not in html
        assert removed not in verifier


def test_public_copy_rule_map_and_banned_claims():
    combined = '\n'.join(
        path.read_text(encoding='utf-8')
        for path in [ROOT / 'README.md', *sorted((ROOT / 'docs').glob('*.md')), ROOT / 'site' / 'index.html', *sorted((ROOT / 'proof').glob('*'))]
    )
    for required in [
        'Real CLI transcript',
        'protected values did not appear in shared Band history in this run',
        'authority-before-disclosure', '3+ agents', 'official Band Agent API',
        'supplier bank-change review', 'Download proof pack', 'receipt-pinned prototype run',
    ]:
        assert required in combined
    for removed in ['old comparison matrix', 'external-work superiority section', 'Other Band projects make agents ' + 'collaborate', 'not another workflow ' + 'room']:
        assert removed.lower() not in combined.lower()

    for banned in [
        'Band privacy ' + 'firewall', 'Band enforces ' + 'consent', 'Band prevents ' + 'replay',
        'guaranteed consent ' + 'enforcement', 'Guaranteed consent ' + 'enforcement',
        'production-' + 'secure', 'production security ' + 'guarantee',
        'independent security audit ' + 'passed', 'independent Band-side audit ' + 'passed',
        'OIDC-grade identity ' + 'assurance', 'OAuth-grade identity ' + 'assurance',
        'public replacement ' + 'complete', 'public push ' + 'complete',
    ]:
        assert banned not in combined


def test_site_check_blocks_production_security_overclaims(tmp_path):
    mutated_root = tmp_path / 'mutated-roomkey'
    shutil.copytree(ROOT, mutated_root, ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache', '*.pyc'))
    for rel in ['README.md', 'site/index.html', 'docs/CLAIMS_BOUNDARY.md']:
        path = mutated_root / rel
        path.write_text(
            path.read_text(encoding='utf-8')
            + '\n\nRoomKey is production-' + 'secure and provides a production security ' + 'guarantee.\n',
            encoding='utf-8',
        )

    proc = subprocess.run(
        [
            sys.executable,
            str(mutated_root / 'scripts' / 'site_check.py'),
            '--banned-claims',
            'README.md',
            'docs',
            'site',
            'src',
            'tests',
            'scripts',
            'proof',
        ],
        cwd=mutated_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 1
    assert 'banned_claim_hits=' in proc.stdout
    assert 'production-' + 'secure' in proc.stdout
    assert 'production security ' + 'guarantee' in proc.stdout


def test_site_check_blocks_stale_download_hash(tmp_path):
    mutated_root = tmp_path / 'mutated-roomkey'
    shutil.copytree(ROOT, mutated_root, ignore=shutil.ignore_patterns('.git', '__pycache__', '.pytest_cache', '*.pyc'))
    evidence_path = mutated_root / 'site' / 'evidence.json'
    evidence = json.loads(evidence_path.read_text(encoding='utf-8'))
    for download in evidence['downloads']:
        if download['href'] == '../proof/ROOMKEY_PROOF_PACK.md':
            download['sha256'] = '0' * 64
            break
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + '\n', encoding='utf-8')

    proc = subprocess.run(
        [sys.executable, str(mutated_root / 'scripts' / 'site_check.py'), 'site/index.html', 'site/evidence.json'],
        cwd=mutated_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 1
    assert 'hash mismatch' in proc.stdout


def test_public_proof_schema_rejects_shallow_downloads_and_bad_proof():
    from jsonschema import Draft202012Validator

    schema = json.loads((ROOT / 'public-proof.schema.json').read_text(encoding='utf-8'))
    evidence = json.loads((ROOT / 'site' / 'evidence.json').read_text(encoding='utf-8'))

    missing_live = json.loads(json.dumps(evidence))
    missing_live.pop('live_receipt_file_sha256')
    assert list(Draft202012Validator(schema).iter_errors(missing_live))

    shallow = json.loads(json.dumps(evidence))
    shallow['downloads'] = [{}, {}, {}, {}, {}]
    assert list(Draft202012Validator(schema).iter_errors(shallow))

    bad_proof = json.loads(json.dumps(evidence))
    bad_proof['proof']['protected_payload_value_posted'] = True
    assert list(Draft202012Validator(schema).iter_errors(bad_proof))
