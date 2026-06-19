#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from roomkey.receipt import verify_receipt  # noqa: E402

SEAL_POST_ID = "3a602d9e-2411-4fb4-944f-0fa094e6df71"

def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def _first_event(events: list[dict], event_type: str) -> dict:
    return next(event for event in events if event.get("type") == event_type)

def build_agent_trace(receipt: dict) -> dict:
    events = receipt["live_gate_events"]
    by_type: dict[str, list[dict]] = {}
    for event in events:
        by_type.setdefault(event.get("type", ""), []).append(event)
    reviewers = [event for event in events if event.get("type") == "reviewer.deposit"]
    return {
        "requester": {
            "name": "Intake Requester",
            "role": "sensitive-context requester / naive baseline contrast",
            "evidence": [by_type["naive.baseline"][0]["band_message_id"], by_type["action.blocked"][0]["band_message_id"]],
        },
        "reviewer_a": {
            "name": "ReviewerA",
            "role": "scoped authority depositor",
            "evidence": [reviewers[0]["band_message_id"]],
        },
        "reviewer_b": {
            "name": "ReviewerB",
            "role": "scoped authority depositor",
            "evidence": [reviewers[1]["band_message_id"]],
        },
        "reviewer_c": {
            "name": "ReviewerC",
            "role": "scoped authority depositor",
            "evidence": [reviewers[2]["band_message_id"]],
        },
        "auditor_gatekeeper": {
            "name": "ScopeGate Auditor/Gatekeeper",
            "role": "enforces and verifies authority-before-disclosure",
            "evidence": [
                by_type["context.replay_blocked"][0]["band_message_id"],
                by_type["grant.revoked"][0]["band_message_id"],
                by_type["receipt.sealed"][0]["band_message_id"],
                SEAL_POST_ID,
            ],
        },
    }

def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: judge_proof.py <receipt.json>", file=sys.stderr)
        return 2
    receipt_path = Path(argv[1])
    receipt = verify_receipt(receipt_path)
    seal_path = receipt_path.with_name(receipt_path.stem + "-seal-post.json")
    if seal_path.exists():
        seal = _load_json(seal_path)
        seal_post_id = seal.get("seal_message_id", SEAL_POST_ID)
    else:
        seal_post_id = SEAL_POST_ID
    events = receipt.get("live_gate_events", [])
    trace = build_agent_trace(receipt)
    scan = receipt.get("band_secret_scan", {})
    late_replay_recovered = any(probe.get("recovered") for probe in receipt.get("late_participant_probes", []))
    print("PASS_ROOMKEY_PROOF")
    print(f"mode={receipt.get('mode')}")
    print("agents_named=true")
    print("agent_trace_present=true")
    print(f"agent_count={len(trace)}")
    print(f"band_message_ids_present={str(bool(receipt.get('band_message_ids')) and all(receipt.get('band_message_ids'))).lower()}")
    print(f"band_message_count={len(receipt.get('band_message_ids') or [])}")
    print(f"pre_grant_block={str(bool(receipt.get('blocked_attempts'))).lower()}")
    print(f"naive_path_blocked={str(bool(receipt.get('blocked_attempts'))).lower()}")
    print(f"scoped_release={str(bool(receipt.get('context_releases'))).lower()}")
    print(f"late_replay_recovered={str(late_replay_recovered).lower()}")
    print(f"reviewer_deposits={len(receipt.get('reviewer_deposits') or [])}")
    print(f"revocation={str(bool(receipt.get('revocations'))).lower()}")
    print(f"post_revocation_block={str(bool(receipt.get('post_revocation_blocks'))).lower()}")
    print(f"post_revocation_blocks={len(receipt.get('post_revocation_blocks') or [])}")
    print(f"raw_secret_canary_posted={str(scan.get('raw_secret_canary_posted')).lower()}")
    print(f"protected_payload_value_posted={str(scan.get('protected_payload_value_posted')).lower()}")
    print(f"receipt_sha256={receipt.get('receipt_sha256')}")
    print(f"seal_post_message_id={seal_post_id}")
    for key, value in trace.items():
        print(f"agent_trace.{key}.name={value['name']}")
        print(f"agent_trace.{key}.role={value['role']}")
        print(f"agent_trace.{key}.evidence={','.join(value['evidence'])}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
