from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest


def _sample_payload() -> dict:
    return {
        "case_id": "vendor-wire-001",
        "safe_metadata": {
            "case_type": "vendor_wire_review",
            "vendor": "PUBLIC_SYNTHETIC_VENDOR",
            "amount_band": "$10k-$25k",
        },
        "protected_payload": {
            "policy_excerpt": "PUBLIC_SYNTHETIC_POLICY_EXCERPT_VALUE",
            "invoice_summary": "PUBLIC_SYNTHETIC_INVOICE_SUMMARY_VALUE",
            "risk_memo": "PUBLIC_SYNTHETIC_RISK_MEMO_VALUE",
            "bank_account": "PUBLIC_SYNTHETIC_BANK_ACCOUNT_VALUE",
        },
        "secret_canary": "PUBLIC_SYNTHETIC_CANARY_VENDOR_WIRE",
    }


@pytest.fixture
def sample_case_dict() -> dict:
    return _sample_payload()


@pytest.fixture
def sample_case_path(tmp_path, sample_case_dict):
    path = tmp_path / "vendor_wire_sensitive.json"
    path.write_text(json.dumps(sample_case_dict, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def future_expiry():
    return datetime.now(timezone.utc) + timedelta(hours=1)
