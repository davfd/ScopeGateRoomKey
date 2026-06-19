from __future__ import annotations

from roomkey.demo_scenarios import run_local_demo


def test_local_demo_emits_required_event_contract(sample_case_path, tmp_path):
    receipt = run_local_demo(sample_case_path, out=tmp_path / "receipt.json")
    event_types = {event["type"] for event in receipt["local_gate_events"]}

    assert {
        "grant.requested",
        "action.blocked",
        "grant.granted",
        "participant.added",
        "context.released",
        "context.replay_blocked",
        "reviewer.deposit",
        "review_gate.adjudicated",
        "grant.revoked",
        "receipt.sealed",
    }.issubset(event_types)
