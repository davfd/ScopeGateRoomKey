from __future__ import annotations

from roomkey.demo_scenarios import LocalDemoHarness
from roomkey.models import AgentRole, ProtectedCase
from roomkey.transcript import leak_radius, secret_seen_before_event


def test_pre_grant_hardened_transcript_has_zero_canary(sample_case_dict):
    case = ProtectedCase.from_dict(sample_case_dict)
    demo = LocalDemoHarness(case)
    demo.start_with_safe_metadata_only()

    transcript = demo.band.export_transcript_sync(demo.room_id)

    assert leak_radius(transcript, case.secret_canary) == 0
    assert secret_seen_before_event(transcript, case.secret_canary, "grant.granted") is False


def test_segmented_transcript_hides_targeted_release_from_late_participant(sample_case_dict):
    case = ProtectedCase.from_dict(sample_case_dict)
    demo = LocalDemoHarness(case)
    demo.start_with_safe_metadata_only()
    demo.grant([AgentRole.ROUTER, AgentRole.EVIDENCE], ["policy_excerpt"])
    demo.release_context(AgentRole.EVIDENCE, "policy_excerpt")
    demo.add_late_participant("Unapproved Auditor")

    late_transcript = demo.band.export_transcript_sync(demo.room_id, viewer="Unapproved Auditor")

    assert case.protected_payload["policy_excerpt"] not in str(late_transcript)
