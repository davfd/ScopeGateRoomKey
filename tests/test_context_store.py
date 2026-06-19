from __future__ import annotations

from datetime import datetime, timedelta, timezone

from roomkey.context_store import ContextStore
from roomkey.models import AgentRole, GrantState, ProtectedCase, ScopedGrant


def _grant() -> ScopedGrant:
    return ScopedGrant(
        room_id="room-1",
        case_id="vendor-wire-001",
        grant_id="grant-1",
        purpose="evaluate simulated vendor action",
        allowed_agents=[AgentRole.EVIDENCE],
        allowed_context_keys=["policy_excerpt"],
        allowed_action_kinds=["send_wire_review"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        human_approver="operator",
        state=GrantState.GRANT_SCOPED,
    )


def test_safe_metadata_does_not_include_secret_canary(sample_case_dict):
    sample_case = ProtectedCase.from_dict(sample_case_dict)
    store = ContextStore.from_cases([sample_case])

    safe = store.get_safe_metadata(sample_case.case_id)

    assert sample_case.secret_canary not in str(safe)
    assert "bank_account" not in str(safe)


def test_release_context_returns_only_one_allowed_key(sample_case_dict):
    sample_case = ProtectedCase.from_dict(sample_case_dict)
    store = ContextStore.from_cases([sample_case])

    release = store.release_context(sample_case.case_id, "policy_excerpt", _grant(), AgentRole.EVIDENCE)

    assert release.allowed is True
    assert release.context_key == "policy_excerpt"
    assert release.value == sample_case.protected_payload["policy_excerpt"]
    assert sample_case.protected_payload["bank_account"] not in release.value


def test_denied_release_returns_no_secret(sample_case_dict):
    sample_case = ProtectedCase.from_dict(sample_case_dict)
    store = ContextStore.from_cases([sample_case])

    release = store.release_context(sample_case.case_id, "bank_account", _grant(), AgentRole.EVIDENCE)

    assert release.allowed is False
    assert release.value is None
    assert sample_case.protected_payload["bank_account"] not in str(release)
