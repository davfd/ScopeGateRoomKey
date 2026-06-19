from __future__ import annotations

from roomkey.demo_scenarios import LocalDemoHarness, run_local_demo
from roomkey.models import AgentRole, ProtectedCase


def test_local_demo_proves_block_grant_release_revoke_and_receipt(sample_case_path, tmp_path):
    receipt = run_local_demo(sample_case_path, out=tmp_path / "receipt.json")

    assert receipt["naive_leak_radius"] > 0
    assert receipt["hardened_leak_radius"] == 0
    assert receipt["blocked_attempts"]
    assert receipt["context_releases"]
    assert receipt["late_participant_probes"]
    assert all(not probe["recovered"] for probe in receipt["late_participant_probes"])
    assert receipt["revocations"]
    assert receipt["secret_canary_pre_grant_seen"] is False
    assert len(receipt["receipt_sha256"]) == 64


def test_late_or_disallowed_participant_cannot_recover_released_key(sample_case_dict):
    sample_case = ProtectedCase.from_dict(sample_case_dict)
    demo = LocalDemoHarness(sample_case)
    demo.start_with_safe_metadata_only()
    demo.grant(
        allowed_agents=[AgentRole.ROUTER, AgentRole.EVIDENCE],
        allowed_context_keys=["policy_excerpt"],
    )
    released = demo.release_context(AgentRole.EVIDENCE, "policy_excerpt")
    assert sample_case.protected_payload["policy_excerpt"] in released.text

    demo.add_late_participant("Unapproved Auditor")
    probe = demo.probe_late_participant_recovery(
        participant="Unapproved Auditor",
        target_context_key="policy_excerpt",
    )

    assert probe.recovered is False
    assert probe.event_type == "context.replay_blocked"
    assert sample_case.protected_payload["policy_excerpt"] not in probe.visible_history_text
