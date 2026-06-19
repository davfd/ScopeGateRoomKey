#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable
ENV = os.environ.copy()
ENV['PYTHONPATH'] = str(ROOT / 'src')
ENV['ROOMKEY_SUBMIT_CHECK'] = '1'
COMMANDS = [
    [PYTHON, '-m', 'roomkey.cli', 'verify', 'receipts/live-band-demo-20260618T185330Z.json'],
    [PYTHON, 'scripts/judge_proof.py', 'receipts/live-band-demo-20260618T185330Z.json'],
    [PYTHON, 'scripts/secret_scan.py'],
    [PYTHON, 'scripts/integrity_check.py'],
    [PYTHON, 'scripts/site_check.py', '--banned-claims', 'README.md', 'docs', 'site', 'src', 'tests', 'scripts', 'proof', 'public-proof.schema.json'],
    [PYTHON, 'scripts/site_check.py', 'site/index.html', 'site/evidence.json'],
    [PYTHON, 'scripts/browser_verifier_contract_check.py', '--root', '.'],
    [PYTHON, '-m', 'pytest', '-q'],
]

def main() -> int:
    for cmd in COMMANDS:
        print('$ ' + ' '.join(cmd))
        proc = subprocess.run(cmd, cwd=ROOT, env=ENV, text=True)
        if proc.returncode != 0:
            return proc.returncode
    print('submit_check=PASS')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
