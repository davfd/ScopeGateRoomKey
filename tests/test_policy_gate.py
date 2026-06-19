from __future__ import annotations

from datetime import datetime, timedelta, timezone

from roomkey.models import AgentRole, GrantState, ScopedGrant
from roomkey.policy import PolicyGate


def make_grant(**overrides) -> ScopedGrant:
    data = {
        "room_id": "room-1",
        "case_id": "vendor-wire-001",
        "grant_id": "grant-1",
        "purpose": "evaluate simulated vendor action",
        "allowed_agents": [AgentRole.ROUTER, AgentRole.EVIDENCE, AgentRole.RISK, AgentRole.ACTION],
        "allowed_context_keys": ["policy_excerpt", "invoice_summary"],
        "allowed_action_kinds": ["send_wire_review"],
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "human_approver": "operator",
        "state": GrantState.GRANT_SCOPED,
    }
    data.update(overrides)
    return ScopedGrant(**data)


def test_pre_grant_action_is_blocked():
    gate = PolicyGate()

    decision = gate.can_execute_action(None, "send_wire_review", human_approved=False)

    assert decision.allowed is False
    assert decision.event_type == "action.blocked"
    assert decision.state == GrantState.NO_GRANT


def test_scoped_grant_allows_only_listed_agent_context():
    grant = make_grant(allowed_agents=[AgentRole.EVIDENCE], allowed_context_keys=["policy_excerpt"])
    gate = PolicyGate()

    assert gate.can_release_context(grant, AgentRole.EVIDENCE, "policy_excerpt", case_id="vendor-wire-001").allowed
    assert not gate.can_release_context(grant, AgentRole.RISK, "policy_excerpt", case_id="vendor-wire-001").allowed
    assert not gate.can_release_context(grant, AgentRole.EVIDENCE, "bank_account", case_id="vendor-wire-001").allowed


def test_revoked_grant_blocks_context_and_action():
    grant = make_grant()
    revoked = PolicyGate().revoke(grant, actor="human", reason="demo revoke")

    assert revoked.state == GrantState.REVOKED
    assert not PolicyGate().can_release_context(revoked, AgentRole.EVIDENCE, "policy_excerpt", case_id="vendor-wire-001").allowed
    assert not PolicyGate().can_execute_action(revoked, "send_wire_review", human_approved=True, case_id="vendor-wire-001").allowed


def test_no_grant_only_intake_and_scopegate_can_join():
    gate = PolicyGate()

    assert gate.can_add_participant(None, AgentRole.INTAKE).allowed
    assert gate.can_add_participant(None, AgentRole.SCOPEGATE).allowed
    assert not gate.can_add_participant(None, AgentRole.EVIDENCE).allowed


def test_expired_grant_denies_release():
    grant = make_grant(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))

    decision = PolicyGate().can_release_context(grant, AgentRole.EVIDENCE, "policy_excerpt", case_id="vendor-wire-001")

    assert decision.allowed is False
    assert decision.event_type == "context.blocked"
