from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from roomkey.models import AgentRole, GateDecision, ProtectedCase, ScopedGrant, role_value
from roomkey.policy import PolicyGate


@dataclass(frozen=True)
class ContextRelease:
    allowed: bool
    case_id: str
    context_key: str
    agent: str
    value: str | None
    decision: GateDecision

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "case_id": self.case_id,
            "context_key": self.context_key,
            "agent": self.agent,
            "value": self.value,
            "decision": self.decision.to_dict(),
        }


class ContextStore:
    def __init__(self, cases: dict[str, ProtectedCase], gate: PolicyGate | None = None) -> None:
        self._cases = dict(cases)
        self._gate = gate or PolicyGate()

    @classmethod
    def from_cases(cls, cases: list[ProtectedCase], gate: PolicyGate | None = None) -> "ContextStore":
        return cls({case.case_id: case for case in cases}, gate=gate)

    def get_safe_metadata(self, case_id: str) -> dict[str, Any]:
        return dict(self._case(case_id).safe_metadata)

    def release_context(
        self,
        case_id: str,
        context_key: str,
        grant: ScopedGrant | None,
        agent: AgentRole | str,
    ) -> ContextRelease:
        decision = self._gate.can_release_context(grant, agent, context_key, case_id=case_id)
        value = None
        if decision.allowed:
            value = self._case(case_id).protected_payload[context_key]
        return ContextRelease(
            allowed=decision.allowed,
            case_id=case_id,
            context_key=context_key,
            agent=role_value(agent),
            value=value,
            decision=decision,
        )

    def _case(self, case_id: str) -> ProtectedCase:
        try:
            return self._cases[case_id]
        except KeyError as exc:
            raise KeyError(f"unknown case_id: {case_id}") from exc
