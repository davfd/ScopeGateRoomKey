from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from roomkey.models import AgentRole, GateDecision, GrantState, ProtectedCase, ScopedGrant, role_value


class PolicyGate:
    """Authority-before-disclosure gate for RoomKey local and live adapters."""

    def __init__(self, revoked_grant_keys: set[tuple[str, str, str]] | None = None) -> None:
        # The revocation registry is explicit instance state. A caller may inject a
        # shared durable registry for a room, but independent gates/tests do not
        # inherit stale process-global revocations.
        self._revoked_grant_keys: set[tuple[str, str, str]] = revoked_grant_keys if revoked_grant_keys is not None else set()

    def request_grant(
        self,
        case: ProtectedCase,
        room_id: str,
        requested_agents: list[AgentRole | str],
        *,
        allowed_context_keys: list[str] | None = None,
        allowed_action_kinds: list[str] | None = None,
        purpose: str = "evaluate simulated enterprise action",
        human_approver: str | None = "operator",
        ttl_seconds: int = 3600,
    ) -> ScopedGrant:
        return ScopedGrant(
            case_id=case.case_id,
            room_id=room_id,
            grant_id=f"grant_{uuid4().hex[:12]}",
            purpose=purpose,
            allowed_agents=list(requested_agents),
            allowed_context_keys=list(allowed_context_keys or []),
            allowed_action_kinds=list(allowed_action_kinds or ["send_wire_review"]),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds),
            human_approver=human_approver,
            state=GrantState.GRANT_SCOPED,
        )

    def can_add_participant(self, grant: ScopedGrant | None, agent: AgentRole | str) -> GateDecision:
        agent_name = role_value(agent)
        if grant is None:
            if agent_name in {AgentRole.INTAKE.value, AgentRole.SCOPEGATE.value}:
                return GateDecision(True, "bootstrap participant", GrantState.NO_GRANT, "participant.added")
            return GateDecision(False, "no scoped grant for participant", GrantState.NO_GRANT, "participant.blocked")
        if self._revoked(grant):
            return GateDecision(False, "grant revoked", grant.state, "participant.blocked")
        if self._expired(grant):
            return GateDecision(False, "grant expired", grant.state, "participant.blocked")
        allowed = {role_value(item) for item in grant.allowed_agents}
        if agent_name in allowed:
            return GateDecision(True, "agent in scoped grant", grant.state, "participant.added")
        return GateDecision(False, "agent outside scoped grant", grant.state, "participant.blocked")

    def can_release_context(
        self,
        grant: ScopedGrant | None,
        agent: AgentRole | str,
        context_key: str,
        *,
        case_id: str | None = None,
    ) -> GateDecision:
        if grant is None:
            return GateDecision(False, "no scoped grant", GrantState.NO_GRANT, "context.blocked")
        if self._revoked(grant):
            return GateDecision(False, "grant revoked", grant.state, "context.blocked")
        if self._expired(grant):
            return GateDecision(False, "grant expired", grant.state, "context.blocked")
        if case_id is None:
            return GateDecision(False, "case id required for scoped release", grant.state, "context.blocked")
        if grant.case_id != case_id:
            return GateDecision(False, "case outside scoped grant", grant.state, "context.blocked")
        allowed_agents = {role_value(item) for item in grant.allowed_agents}
        if role_value(agent) not in allowed_agents:
            return GateDecision(False, "agent outside scoped grant", grant.state, "context.blocked")
        if context_key not in grant.allowed_context_keys:
            return GateDecision(False, "context key outside scoped grant", grant.state, "context.blocked")
        return GateDecision(True, "context key released under scoped grant", grant.state, "context.released")

    def can_execute_action(
        self,
        grant: ScopedGrant | None,
        action_kind: str,
        human_approved: bool,
        *,
        case_id: str | None = None,
    ) -> GateDecision:
        if grant is None:
            return GateDecision(False, "no scoped grant", GrantState.NO_GRANT, "action.blocked")
        if self._revoked(grant):
            return GateDecision(False, "grant revoked", grant.state, "action.blocked")
        if self._expired(grant):
            return GateDecision(False, "grant expired", grant.state, "action.blocked")
        if case_id is None:
            return GateDecision(False, "case id required for scoped action", grant.state, "action.blocked")
        if grant.case_id != case_id:
            return GateDecision(False, "case outside scoped grant", grant.state, "action.blocked")
        if not grant.human_approver:
            return GateDecision(False, "human approver required", grant.state, "action.blocked")
        if action_kind not in grant.allowed_action_kinds:
            return GateDecision(False, "action kind outside scoped grant", grant.state, "action.blocked")
        if not human_approved:
            return GateDecision(False, "human approval required", grant.state, "action.blocked")
        return GateDecision(True, "human-approved scoped action", GrantState.HUMAN_APPROVED, "action.allowed")

    def revoke(self, grant: ScopedGrant, actor: str, reason: str) -> ScopedGrant:
        self._revoked_grant_keys.add(self._grant_key(grant))
        grant.state = GrantState.REVOKED
        return replace(grant, state=GrantState.REVOKED)

    @classmethod
    def _grant_key(cls, grant: ScopedGrant) -> tuple[str, str, str]:
        return (grant.room_id, grant.case_id, grant.grant_id)

    def _revoked(self, grant: ScopedGrant) -> bool:
        return grant.state == GrantState.REVOKED or self._grant_key(grant) in self._revoked_grant_keys

    @staticmethod
    def _expired(grant: ScopedGrant) -> bool:
        return grant.expires_at <= datetime.now(timezone.utc)
