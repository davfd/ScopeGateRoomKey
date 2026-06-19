from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from roomkey.band.in_memory import InMemoryBandClient
from roomkey.context_store import ContextStore
from roomkey.models import AgentRole, GateEvent, ProtectedCase, ScopedGrant, role_value
from roomkey.policy import PolicyGate
from roomkey.receipt import hash_json, seal_receipt, write_receipt
from roomkey.transcript import leak_radius, secret_seen_before_event


@dataclass(frozen=True)
class ReleaseView:
    text: str
    context_key: str
    agent: str


@dataclass(frozen=True)
class LateParticipantProbe:
    participant: str
    target_context_key: str
    recovered: bool
    event_type: str
    visible_history_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "participant": self.participant,
            "target_context_key": self.target_context_key,
            "recovered": self.recovered,
            "event_type": self.event_type,
            "visible_history_text_sha256": sha256(self.visible_history_text.encode("utf-8")).hexdigest(),
        }


def _value_sha(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


class LocalDemoHarness:
    def __init__(self, sample_case: ProtectedCase, *, room_id: str | None = None) -> None:
        self.case = sample_case
        self.room_id = room_id or f"roomkey-local-{sample_case.case_id}"
        self.band = InMemoryBandClient()
        self.gate = PolicyGate()
        self.store = ContextStore.from_cases([sample_case])
        self.grant_obj: ScopedGrant | None = None
        self.local_gate_events: list[dict[str, Any]] = []
        self.blocked_attempts: list[dict[str, Any]] = []
        self.context_releases: list[dict[str, Any]] = []
        self.late_participant_probes: list[dict[str, Any]] = []
        self.revocations: list[dict[str, Any]] = []
        self.reviewer_deposits: list[dict[str, Any]] = []
        self.review_gate: dict[str, Any] = {}

    def start_with_safe_metadata_only(self) -> None:
        self.band.add_participant_sync(self.room_id, AgentRole.INTAKE)
        self.band.add_participant_sync(self.room_id, AgentRole.SCOPEGATE)
        self.band.send_message_sync(
            self.room_id,
            AgentRole.INTAKE,
            f"Safe case metadata only: {json.dumps(self.case.safe_metadata, sort_keys=True)}",
        )

    def block_pre_grant_action(self) -> None:
        decision = self.gate.can_execute_action(None, "send_wire_review", human_approved=False)
        attempt = {
            "phase": "pre_grant",
            "action_kind": "send_wire_review",
            "decision": decision.to_dict(),
        }
        self.blocked_attempts.append(attempt)
        self._emit(decision.event_type, AgentRole.ACTION, attempt)

    def grant(
        self,
        allowed_agents: list[AgentRole | str],
        allowed_context_keys: list[str],
    ) -> ScopedGrant:
        self._emit(
            "grant.requested",
            AgentRole.SCOPEGATE,
            {
                "case_id": self.case.case_id,
                "requested_agents": [role_value(agent) for agent in allowed_agents],
                "requested_context_keys": list(allowed_context_keys),
            },
        )
        self.grant_obj = self.gate.request_grant(
            self.case,
            self.room_id,
            allowed_agents,
            allowed_context_keys=allowed_context_keys,
            allowed_action_kinds=["send_wire_review"],
            human_approver="operator",
        )
        self._emit(
            "grant.granted",
            AgentRole.SCOPEGATE,
            {
                "grant_id": self.grant_obj.grant_id,
                "purpose": self.grant_obj.purpose,
                "allowed_agents": [role_value(agent) for agent in allowed_agents],
                "allowed_context_keys": list(allowed_context_keys),
                "allowed_action_kinds": ["send_wire_review"],
                "expires_at": self.grant_obj.expires_at.isoformat(),
            },
        )
        return self.grant_obj

    def add_participant_through_gate(self, agent: AgentRole | str) -> bool:
        decision = self.gate.can_add_participant(self.grant_obj, agent)
        payload = {"agent": role_value(agent), "decision": decision.to_dict()}
        if decision.allowed:
            self.band.add_participant_sync(self.room_id, agent)
        self._emit(decision.event_type, AgentRole.ROUTER, payload)
        return decision.allowed

    def release_context(self, agent: AgentRole | str, context_key: str) -> ReleaseView:
        release = self.store.release_context(self.case.case_id, context_key, self.grant_obj, agent)
        if release.allowed and release.value is not None:
            self.band.send_message_sync(
                self.room_id,
                agent,
                f"Scoped protected context `{context_key}`: {release.value}",
                visible_to=[agent],
            )
            receipt_release = {
                "case_id": self.case.case_id,
                "context_key": context_key,
                "agent": role_value(agent),
                "value_sha256": _value_sha(release.value),
                "value_chars": len(release.value),
            }
            self.context_releases.append(receipt_release)
            self._emit("context.released", agent, receipt_release)
            return ReleaseView(text=release.value, context_key=context_key, agent=role_value(agent))

        blocked = {
            "case_id": self.case.case_id,
            "context_key": context_key,
            "agent": role_value(agent),
            "decision": release.decision.to_dict(),
        }
        self.blocked_attempts.append(blocked)
        self._emit(release.decision.event_type, agent, blocked)
        return ReleaseView(text="", context_key=context_key, agent=role_value(agent))

    def add_late_participant(self, participant: str) -> None:
        self.band.add_participant_sync(self.room_id, participant)
        self._emit("participant.added", AgentRole.ROUTER, {"agent": participant, "late": True})

    def probe_late_participant_recovery(self, participant: str, target_context_key: str) -> LateParticipantProbe:
        transcript = self.band.export_transcript_sync(self.room_id, viewer=participant)
        visible_history_text = json.dumps(transcript, sort_keys=True)
        target_value = self.case.protected_payload[target_context_key]
        release = self.store.release_context(self.case.case_id, target_context_key, self.grant_obj, participant)
        recovered = target_value in visible_history_text or (release.allowed and release.value == target_value)
        event_type = "context.replay_blocked" if not recovered else "context.replay_leaked"
        probe = LateParticipantProbe(
            participant=participant,
            target_context_key=target_context_key,
            recovered=recovered,
            event_type=event_type,
            visible_history_text=visible_history_text,
        )
        probe_dict = probe.to_dict()
        self.late_participant_probes.append(probe_dict)
        self._emit(event_type, participant, probe_dict)
        return probe

    def run_review_gate(self) -> None:
        reviewer_plan = [
            (AgentRole.REVIEWER_A, "policy_excerpt", "ALLOW"),
            (AgentRole.REVIEWER_B, "invoice_summary", "ALLOW"),
            (AgentRole.REVIEWER_C, "risk_memo", "HUMAN_ESCALATE"),
        ]
        for reviewer, context_key, verdict in reviewer_plan:
            self.add_participant_through_gate(reviewer)
            release = self.release_context(reviewer, context_key)
            value_hash = _value_sha(release.text) if release.text else None
            deposit = {
                "reviewer": reviewer.value,
                "verdict": verdict,
                "received_context_keys": [context_key] if release.text else [],
                "context_value_sha256": value_hash,
                "independent": True,
            }
            self.reviewer_deposits.append(deposit)
            self.band.send_message_sync(
                self.room_id,
                reviewer,
                f"{reviewer.value} deposit: {verdict} on scoped key `{context_key}` hash={value_hash}",
            )
            self._emit("reviewer.deposit", reviewer, deposit)

        final_outcome = self._adjudicate([deposit["verdict"] for deposit in self.reviewer_deposits])
        self.review_gate = {
            "name": "RoomKey Review Gate",
            "reviewer_count": 3,
            "threshold_rule": "BOUNCE if >=2 BOUNCE; HUMAN_ESCALATE if any HUMAN_ESCALATE; else ALLOW",
            "final_outcome": final_outcome,
        }
        self._emit("review_gate.adjudicated", AgentRole.ADJUDICATOR, self.review_gate)

    def revoke_and_probe(self) -> None:
        if self.grant_obj is None:
            raise RuntimeError("cannot revoke before grant")
        self.grant_obj = self.gate.revoke(self.grant_obj, actor="operator", reason="demo complete")
        revocation = {"grant_id": self.grant_obj.grant_id, "actor": "operator", "reason": "demo complete"}
        self.revocations.append(revocation)
        self._emit("grant.revoked", AgentRole.SCOPEGATE, revocation)
        decision = self.gate.can_execute_action(self.grant_obj, "send_wire_review", human_approved=True, case_id=self.case.case_id)
        blocked = {"phase": "post_revocation", "action_kind": "send_wire_review", "decision": decision.to_dict()}
        self.blocked_attempts.append(blocked)
        self._emit(decision.event_type, AgentRole.ACTION, blocked)

    @staticmethod
    def _adjudicate(verdicts: list[str]) -> str:
        if verdicts.count("BOUNCE") >= 2:
            return "BOUNCE"
        if "HUMAN_ESCALATE" in verdicts:
            return "HUMAN_ESCALATE"
        return "ALLOW"

    def _emit(self, event_type: str, actor: AgentRole | str, payload: dict[str, Any]) -> dict[str, Any]:
        event = GateEvent.create(room_id=self.room_id, type=event_type, actor=actor, payload=payload)
        event_dict = event.to_dict()
        self.local_gate_events.append(event_dict)
        self.band.send_event_sync(self.room_id, event)
        return event_dict


def _load_case(case_path: str | Path) -> ProtectedCase:
    return ProtectedCase.from_dict(json.loads(Path(case_path).read_text(encoding="utf-8")))


def _naive_leak_radius(case: ProtectedCase) -> int:
    band = InMemoryBandClient()
    room_id = f"naive-{case.case_id}"
    band.add_participant_sync(room_id, AgentRole.INTAKE)
    band.send_message_sync(
        room_id,
        AgentRole.INTAKE,
        "NAIVE BASELINE leaked payload: "
        + json.dumps({"metadata": case.safe_metadata, "protected": case.protected_payload, "canary": case.secret_canary}, sort_keys=True),
    )
    return leak_radius(band.export_transcript_sync(room_id), case.secret_canary)


def run_local_demo(case_path: str | Path, out: str | Path | None = None) -> dict[str, Any]:
    case = _load_case(case_path)
    naive_radius = _naive_leak_radius(case)

    demo = LocalDemoHarness(case)
    demo.start_with_safe_metadata_only()
    pregrant_transcript = demo.band.export_transcript_sync(demo.room_id)
    hardened_radius = leak_radius(pregrant_transcript, case.secret_canary)
    secret_pregrant = secret_seen_before_event(pregrant_transcript, case.secret_canary, "grant.granted")

    demo.block_pre_grant_action()
    demo.grant(
        allowed_agents=[
            AgentRole.ROUTER,
            AgentRole.EVIDENCE,
            AgentRole.RISK,
            AgentRole.ACTION,
            AgentRole.REVIEWER_A,
            AgentRole.REVIEWER_B,
            AgentRole.REVIEWER_C,
        ],
        allowed_context_keys=["policy_excerpt", "invoice_summary", "risk_memo"],
    )
    for agent in [AgentRole.ROUTER, AgentRole.EVIDENCE, AgentRole.RISK, AgentRole.ACTION]:
        demo.add_participant_through_gate(agent)
    demo.release_context(AgentRole.EVIDENCE, "policy_excerpt")
    demo.add_late_participant("Unapproved Auditor")
    demo.probe_late_participant_recovery("Unapproved Auditor", "policy_excerpt")
    demo.run_review_gate()
    demo.revoke_and_probe()
    demo._emit("receipt.sealed", AgentRole.SCOPEGATE, {"mode": "local", "case_id": case.case_id})

    transcript = demo.band.export_transcript_sync(demo.room_id)
    receipt = {
        "project": "RoomKey by ScopeGate",
        "mode": "local_fake_band",
        "room_id": demo.room_id,
        "case_id": case.case_id,
        "grant_id": demo.grant_obj.grant_id if demo.grant_obj else None,
        "agent_handles": [role.value for role in AgentRole],
        "grant": demo.grant_obj.to_dict() if demo.grant_obj else None,
        "band_event_ids": [event["event_id"] for event in demo.local_gate_events],
        "local_gate_events": demo.local_gate_events,
        "blocked_attempts": demo.blocked_attempts,
        "context_releases": demo.context_releases,
        "late_participant_probes": demo.late_participant_probes,
        "reviewer_deposits": demo.reviewer_deposits,
        "review_gate": demo.review_gate,
        "revocations": demo.revocations,
        "naive_leak_radius": naive_radius,
        "hardened_leak_radius": hardened_radius,
        "transcript_sha256": hash_json(transcript),
        "policy_log_sha256": hash_json(demo.local_gate_events),
        "secret_canary_pre_grant_seen": secret_pregrant,
        "sealed_at": demo.local_gate_events[-1]["created_at"],
    }
    sealed = seal_receipt(receipt)
    if out is not None:
        write_receipt(sealed, out)
    return sealed
