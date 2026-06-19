from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4


class GrantState(StrEnum):
    NO_GRANT = "NO_GRANT"
    CONSENT_REQUESTED = "CONSENT_REQUESTED"
    GRANT_SCOPED = "GRANT_SCOPED"
    HUMAN_APPROVED = "HUMAN_APPROVED"
    REVOKED = "REVOKED"
    RECEIPT_SEALED = "RECEIPT_SEALED"


class AgentRole(StrEnum):
    INTAKE = "Intake"
    SCOPEGATE = "ScopeGate"
    ROUTER = "Router"
    EVIDENCE = "Evidence"
    RISK = "Risk"
    ACTION = "Action"
    REVIEWER_A = "ReviewerA"
    REVIEWER_B = "ReviewerB"
    REVIEWER_C = "ReviewerC"
    ADJUDICATOR = "Adjudicator"


def role_value(role: AgentRole | str) -> str:
    return role.value if isinstance(role, AgentRole) else str(role)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass
class ScopedGrant:
    case_id: str
    room_id: str
    grant_id: str
    purpose: str
    allowed_agents: list[AgentRole | str]
    allowed_context_keys: list[str]
    allowed_action_kinds: list[str]
    expires_at: datetime
    human_approver: str | None = None
    state: GrantState = GrantState.CONSENT_REQUESTED

    def __post_init__(self) -> None:
        self.expires_at = parse_datetime(self.expires_at)
        self.state = GrantState(self.state)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "room_id": self.room_id,
            "grant_id": self.grant_id,
            "purpose": self.purpose,
            "allowed_agents": [role_value(agent) for agent in self.allowed_agents],
            "allowed_context_keys": list(self.allowed_context_keys),
            "allowed_action_kinds": list(self.allowed_action_kinds),
            "expires_at": self.expires_at.isoformat(),
            "human_approver": self.human_approver,
            "state": self.state.value,
        }


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason: str
    state: GrantState
    event_type: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "state": self.state.value,
            "event_type": self.event_type,
        }


@dataclass
class GateEvent:
    event_id: str
    room_id: str
    type: str
    actor: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    visible_to: list[str] | None = None

    @classmethod
    def create(
        cls,
        *,
        room_id: str,
        type: str,
        actor: AgentRole | str,
        payload: dict[str, Any] | None = None,
        visible_to: list[AgentRole | str] | None = None,
    ) -> "GateEvent":
        return cls(
            event_id=f"evt_{uuid4().hex[:12]}",
            room_id=room_id,
            type=type,
            actor=role_value(actor),
            payload=payload or {},
            visible_to=[role_value(item) for item in visible_to] if visible_to else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "room_id": self.room_id,
            "type": self.type,
            "actor": self.actor,
            "payload": to_jsonable(self.payload),
            "created_at": self.created_at.isoformat(),
            "visible_to": list(self.visible_to) if self.visible_to else None,
        }


@dataclass(frozen=True)
class ProtectedCase:
    case_id: str
    safe_metadata: dict[str, Any]
    protected_payload: dict[str, str]
    secret_canary: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProtectedCase":
        return cls(
            case_id=str(data["case_id"]),
            safe_metadata=dict(data.get("safe_metadata", {})),
            protected_payload={str(k): str(v) for k, v in dict(data.get("protected_payload", {})).items()},
            secret_canary=str(data["secret_canary"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "safe_metadata": dict(self.safe_metadata),
            "protected_payload": dict(self.protected_payload),
            "secret_canary": self.secret_canary,
        }


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(v) for v in value]
    return value
