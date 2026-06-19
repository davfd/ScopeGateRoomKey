from __future__ import annotations

from pathlib import Path

def test_readme_states_public_judge_path_without_banned_band_claims():
    readme = Path('README.md').read_text(encoding='utf-8')
    assert 'make submit-check' in readme
    assert 'authority-before-disclosure' in readme
    assert 'receipt-pinned prototype' in readme
    assert 'RoomKey adds a disclosure gate to the room.' in readme
    assert 'protected values did not appear in shared Band history in this run' in readme
    assert 'Key insight' in readme
    assert 'canonical_receipt_sha256' in readme
    assert 'browser_receipt_hash' in readme
    for banned in [
        'Band privacy ' + 'firewall', 'Band enforces ' + 'consent', 'Guaranteed consent ' + 'enforcement',
        'guaranteed consent ' + 'enforcement', 'Band prevents ' + 'replay',
        'production-' + 'secure', 'production security ' + 'guarantee',
        'independent security audit ' + 'passed', 'independent Band-side audit ' + 'passed',
        'OIDC-grade identity ' + 'assurance', 'OAuth-grade identity ' + 'assurance',
        'public replacement ' + 'complete', 'public push ' + 'complete',
    ]:
        assert banned not in readme
