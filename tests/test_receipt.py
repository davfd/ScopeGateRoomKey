from __future__ import annotations

import json

import pytest

from roomkey.demo_scenarios import run_local_demo
from roomkey.receipt import ReceiptVerificationError, hash_json, seal_receipt, verify_receipt


def test_local_receipt_verifies(sample_case_path, tmp_path):
    out = tmp_path / "receipt.json"
    receipt = run_local_demo(sample_case_path, out=out)

    verified = verify_receipt(out)

    assert verified["receipt_sha256"] == receipt["receipt_sha256"]


def test_tampered_receipt_hash_fails(sample_case_path, tmp_path):
    out = tmp_path / "receipt.json"
    run_local_demo(sample_case_path, out=out)
    data = json.loads(out.read_text(encoding="utf-8"))
    data["blocked_attempts"] = []
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")

    with pytest.raises(ReceiptVerificationError):
        verify_receipt(out)


def test_reviewer_deposits_before_replay_block_fail_even_with_valid_hash(sample_case_path, tmp_path):
    out = tmp_path / "receipt.json"
    run_local_demo(sample_case_path, out=out)
    data = json.loads(out.read_text(encoding="utf-8"))
    events = data["local_gate_events"]
    replay_index = next(i for i, event in enumerate(events) if event["type"] == "context.replay_blocked")
    reviewer_index = next(i for i, event in enumerate(events) if event["type"] == "reviewer.deposit")
    reviewer_event = events.pop(reviewer_index)
    events.insert(replay_index, reviewer_event)
    data["local_gate_events"] = events
    data["policy_log_sha256"] = hash_json(events)
    resealed = seal_receipt(data)
    out.write_text(json.dumps(resealed, indent=2), encoding="utf-8")

    with pytest.raises(ReceiptVerificationError, match="event order"):
        verify_receipt(out)


def test_adjudication_before_all_reviewer_deposits_fails_even_with_valid_hash(sample_case_path, tmp_path):
    out = tmp_path / "receipt.json"
    run_local_demo(sample_case_path, out=out)
    data = json.loads(out.read_text(encoding="utf-8"))
    events = data["local_gate_events"]
    last_reviewer_index = max(i for i, event in enumerate(events) if event["type"] == "reviewer.deposit")
    adjudicated_index = next(i for i, event in enumerate(events) if event["type"] == "review_gate.adjudicated")
    reviewer_event = events.pop(last_reviewer_index)
    # Move one required reviewer deposit after adjudication while keeping hashes internally valid.
    events.insert(adjudicated_index + 1, reviewer_event)
    data["local_gate_events"] = events
    data["policy_log_sha256"] = hash_json(events)
    resealed = seal_receipt(data)
    out.write_text(json.dumps(resealed, indent=2), encoding="utf-8")

    with pytest.raises(ReceiptVerificationError, match="event order"):
        verify_receipt(out)
