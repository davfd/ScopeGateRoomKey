#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', '.venv', '__pycache__', '.pytest_cache'}
SKIP_SUFFIXES = {'.pyc', '.png', '.jpg', '.jpeg', '.gif', '.mp4', '.tar', '.gz', '.zip'}
SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|password|token)\s*=\s*["\'](?!\[REDACTED)[^"\']{12,}["\']'),
    re.compile(r'(?i)"(api[_-]?key|secret|password|token|passwd)"\s*:\s*"(?!\[REDACTED)[^"\']{12,}"'),
    re.compile(r'(?i)bearer\s+[a-z0-9_\-\.]{20,}'),
    re.compile(r'sk-[A-Za-z0-9_\-]{20,}'),
]
ALLOW_SNIPPETS = ['[REDACTED]', 'sha256', 'receipt_sha256', 'secret_scan', 'secret canary', 'raw_secret_canary_posted']
PUBLIC_PLACEHOLDER_PREFIXES = ('PUBLIC_SYNTHETIC_', 'DEMO_PUBLIC_PLACEHOLDER_')

def _allowed_public_placeholder(value: object) -> bool:
    return isinstance(value, str) and value.startswith(PUBLIC_PLACEHOLDER_PREFIXES)

def _scan_sensitive_json(path: Path, text: str) -> list[str]:
    findings: list[str] = []
    if path.suffix.lower() != '.json':
        return findings
    try:
        data = __import__('json').loads(text)
    except Exception:
        return findings
    def walk(value: object, path_bits: list[str], under_protected_payload: bool = False) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                child_path = [*path_bits, key_text]
                sensitive_key = key_text in {'secret_canary', 'api_key', 'api-key', 'password', 'token', 'passwd'}
                if key_text == 'protected_payload':
                    walk(child, child_path, True)
                elif sensitive_key and isinstance(child, str) and child and not _allowed_public_placeholder(child):
                    findings.append(f"{path.relative_to(ROOT)}:{'.'.join(child_path)}:[REDACTED]")
                else:
                    walk(child, child_path, under_protected_payload)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, [*path_bits, str(index)], under_protected_payload)
        elif under_protected_payload and isinstance(value, str) and value and not _allowed_public_placeholder(value):
            findings.append(f"{path.relative_to(ROOT)}:{'.'.join(path_bits)}:[REDACTED]")

    walk(data, [])
    return findings

def iter_files():
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        yield path

def main() -> int:
    findings = []
    for path in iter_files():
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        findings.extend(_scan_sensitive_json(path, text))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if any(allow in line for allow in ALLOW_SNIPPETS):
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{lineno}:{line.strip()[:160]}")
    if findings:
        print('secret_scan_findings=')
        for finding in findings:
            print(finding)
        return 1
    print('secret_scan_findings=[]')
    print('finding_count=0')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
