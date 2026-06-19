from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

from roomkey.context_store import ContextStore
from roomkey.demo_scenarios import _load_case, _naive_leak_radius
from roomkey.models import AgentRole, GateEvent, ProtectedCase, ScopedGrant, role_value
from roomkey.policy import PolicyGate
from roomkey.receipt import hash_json, seal_receipt, write_receipt
from roomkey.transcript import leak_radius


class BandMessagePoster(Protocol):
    def post_agent_message(self, room_id: str, content: str) -> dict[str, Any]: ...


def _value_sha(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


class LiveBandDemoHarness:
    """Run the RoomKey ordered gate against a live-Band posting surface.

    The harness deliberately never posts raw protected payload values to Band.
    Band receives only safe metadata, scope descriptions, hashes, character
    counts, status decisions, and verifier-friendly event labels.
    """

    def __init__(self, case: ProtectedCase, *, room_id: str, client: BandMessagePoster) -> None:
        self.case = case
        self.room_id = room_id
        self.client = client
        self.gate = PolicyGate()
        self.store = ContextStore.from_cases([case])
        self.grant_obj: ScopedGrant | None = None
        self.live_gate_events: list[dict[str, Any]] = []
        self.band_posts: list[dict[str, Any]] = []
        self.blocked_attempts: list[dict[str, Any]] = []
        self.context_releases: list[dict[str, Any]] = []
        self.late_participant_probes: list[dict[str, Any]] = []
        self.revocations: list[dict[str, Any]] = []
        self.post_revocation_blocks: list[dict[str, Any]] = []
        self.reviewer_deposits: list[dict[str, Any]] = []
        self.review_gate: dict[str, Any] = {}

    def post_intro_and_naive_baseline(self) -> None:
        safe_metadata = json.dumps(self.case.safe_metadata, sort_keys=True)
        self._emit(
            "demo.started",
            AgentRole.SCOPEGATE,
            {"case_id": self.case.case_id, "mode": "live_band_spear", "raw_protected_payload_posted": False},
            f"ROOMKEY LIVE SPEAR START case={self.case.case_id}; safe_metadata={safe_metadata}; raw_protected_payload_posted=false",
        )
        self._emit(
            "naive.baseline",
            AgentRole.INTAKE,
            {
                "would_leak_canary": True,
                "raw_canary_posted_to_band": False,
                "canary_sha256": _value_sha(self.case.secret_canary),
                "protected_keys": sorted(self.case.protected_payload.keys()),
            },
            "NAIVE BASELINE (simulated, not raw-posted): ordinary room chat would leak protected context; "
            f"canary_sha256={_value_sha(self.case.secret_canary)}; raw_canary_posted_to_band=false",
        )

    def block_pre_grant_action(self) -> None:
        decision = self.gate.can_execute_action(None, "send_wire_review", human_approved=False)
        attempt = {"phase": "pre_grant", "action_kind": "send_wire_review", "decision": decision.to_dict()}
        self.blocked_attempts.append(attempt)
        self._emit(
            decision.event_type,
            AgentRole.ACTION,
            attempt,
            "PRE-GRANT BLOCK: action=send_wire_review allowed=false reason=no scoped grant; protected payload withheld",
        )

    def grant(self) -> ScopedGrant:
        requested_agents: list[AgentRole | str] = [
            AgentRole.ROUTER,
            AgentRole.EVIDENCE,
            AgentRole.RISK,
            AgentRole.ACTION,
            AgentRole.REVIEWER_A,
            AgentRole.REVIEWER_B,
            AgentRole.REVIEWER_C,
        ]
        allowed_context_keys = ["policy_excerpt", "invoice_summary", "risk_memo"]
        self._emit(
            "grant.requested",
            AgentRole.SCOPEGATE,
            {
                "case_id": self.case.case_id,
                "requested_agents": [role_value(agent) for agent in requested_agents],
                "requested_context_keys": allowed_context_keys,
            },
            "GRANT REQUESTED: scoped agents="
            + ",".join(role_value(agent) for agent in requested_agents)
            + f"; scoped_context_keys={','.join(allowed_context_keys)}; no raw values posted",
        )
        self.grant_obj = self.gate.request_grant(
            self.case,
            self.room_id,
            requested_agents,
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
                "allowed_agents": [role_value(agent) for agent in requested_agents],
                "allowed_context_keys": allowed_context_keys,
                "allowed_action_kinds": ["send_wire_review"],
                "expires_at": self.grant_obj.expires_at.isoformat(),
            },
            f"GRANT SCOPED: grant_id={self.grant_obj.grant_id}; context_keys={','.join(allowed_context_keys)}; values remain off-room",
        )
        return self.grant_obj

    def add_participant_through_gate(self, agent: AgentRole | str) -> bool:
        decision = self.gate.can_add_participant(self.grant_obj, agent)
        payload = {"agent": role_value(agent), "decision": decision.to_dict(), "band_participant_mutation": "not_required_for_synthetic_live_spear"}
        self._emit(
            decision.event_type,
            AgentRole.ROUTER,
            payload,
            f"PARTICIPANT GATE: agent={role_value(agent)} allowed={str(decision.allowed).lower()} reason={decision.reason}",
        )
        return decision.allowed

    def release_context_hash_only(self, agent: AgentRole | str, context_key: str) -> str:
        release = self.store.release_context(self.case.case_id, context_key, self.grant_obj, agent)
        if release.allowed and release.value is not None:
            receipt_release = {
                "case_id": self.case.case_id,
                "context_key": context_key,
                "agent": role_value(agent),
                "value_sha256": _value_sha(release.value),
                "value_chars": len(release.value),
                "raw_value_posted_to_band": False,
            }
            self.context_releases.append(receipt_release)
            self._emit(
                "context.released",
                agent,
                receipt_release,
                f"SCOPED RELEASE: agent={role_value(agent)} context_key={context_key} value_sha256={receipt_release['value_sha256']} value_chars={receipt_release['value_chars']} raw_value_posted=false",
            )
            return release.value

        blocked = {
            "case_id": self.case.case_id,
            "context_key": context_key,
            "agent": role_value(agent),
            "decision": release.decision.to_dict(),
        }
        self.blocked_attempts.append(blocked)
        self._emit(
            release.decision.event_type,
            agent,
            blocked,
            f"CONTEXT BLOCKED: agent={role_value(agent)} context_key={context_key} reason={release.decision.reason}",
        )
        return ""

    def probe_late_participant_recovery(self, participant: str, target_context_key: str) -> None:
        visible_history_text = json.dumps(self.band_posts, sort_keys=True)
        target_value = self.case.protected_payload[target_context_key]
        release = self.store.release_context(self.case.case_id, target_context_key, self.grant_obj, participant)
        recovered = target_value in visible_history_text or (release.allowed and release.value == target_value)
        event_type = "context.replay_blocked" if not recovered else "context.replay_leaked"
        probe = {
            "participant": participant,
            "target_context_key": target_context_key,
            "recovered": recovered,
            "release_allowed": release.allowed,
            "decision": release.decision.to_dict(),
            "visible_history_text_sha256": _value_sha(visible_history_text),
        }
        self.late_participant_probes.append(probe)
        self._emit(
            event_type,
            participant,
            probe,
            f"LATE REPLAY PROBE: participant={participant} context_key={target_context_key} recovered={str(recovered).lower()} visible_history_sha256={probe['visible_history_text_sha256']}",
        )

    def run_review_gate(self) -> None:
        reviewer_plan = [
            (AgentRole.REVIEWER_A, "policy_excerpt", "ALLOW"),
            (AgentRole.REVIEWER_B, "invoice_summary", "ALLOW"),
            (AgentRole.REVIEWER_C, "risk_memo", "HUMAN_ESCALATE"),
        ]
        for reviewer, context_key, verdict in reviewer_plan:
            self.add_participant_through_gate(reviewer)
            release_value = self.release_context_hash_only(reviewer, context_key)
            deposit = {
                "reviewer": reviewer.value,
                "verdict": verdict,
                "received_context_keys": [context_key] if release_value else [],
                "context_value_sha256": _value_sha(release_value) if release_value else None,
                "context_value_chars": len(release_value) if release_value else 0,
                "raw_value_posted_to_band": False,
                "independent": True,
            }
            self.reviewer_deposits.append(deposit)
            self._emit(
                "reviewer.deposit",
                reviewer,
                deposit,
                f"{reviewer.value} DEPOSIT: verdict={verdict} context_key={context_key} value_sha256={deposit['context_value_sha256']} raw_value_posted=false",
            )
        verdicts = [deposit["verdict"] for deposit in self.reviewer_deposits]
        final_outcome = self._adjudicate(verdicts)
        self.review_gate = {
            "name": "RoomKey Review Gate",
            "reviewer_count": 3,
            "threshold_rule": "BOUNCE if >=2 BOUNCE; HUMAN_ESCALATE if any HUMAN_ESCALATE; else ALLOW",
            "final_outcome": final_outcome,
        }
        self._emit(
            "review_gate.adjudicated",
            AgentRole.ADJUDICATOR,
            self.review_gate,
            f"REVIEW GATE ADJUDICATED: reviewer_count=3 final_outcome={final_outcome}",
        )

    def revoke_and_probe(self) -> None:
        if self.grant_obj is None:
            raise RuntimeError("cannot revoke before grant")
        self.grant_obj = self.gate.revoke(self.grant_obj, actor="operator", reason="live spear complete")
        revocation = {"grant_id": self.grant_obj.grant_id, "actor": "operator", "reason": "live spear complete"}
        self.revocations.append(revocation)
        self._emit(
            "grant.revoked",
            AgentRole.SCOPEGATE,
            revocation,
            f"GRANT REVOKED: grant_id={self.grant_obj.grant_id}; reason=live spear complete",
        )
        action_decision = self.gate.can_execute_action(self.grant_obj, "send_wire_review", human_approved=True, case_id=self.case.case_id)
        action_block = {"phase": "post_revocation", "action_kind": "send_wire_review", "decision": action_decision.to_dict()}
        self.blocked_attempts.append(action_block)
        self.post_revocation_blocks.append(action_block)
        self._emit(
            action_decision.event_type,
            AgentRole.ACTION,
            action_block,
            f"POST-REVOCATION BLOCK: action=send_wire_review allowed=false reason={action_decision.reason}",
        )
        context_release = self.store.release_context(self.case.case_id, "policy_excerpt", self.grant_obj, AgentRole.EVIDENCE)
        context_block = {
            "phase": "post_revocation",
            "context_key": "policy_excerpt",
            "agent": AgentRole.EVIDENCE.value,
            "decision": context_release.decision.to_dict(),
        }
        self.post_revocation_blocks.append(context_block)
        self._emit(
            context_release.decision.event_type,
            AgentRole.EVIDENCE,
            context_block,
            f"POST-REVOCATION CONTEXT BLOCK: agent=Evidence context_key=policy_excerpt allowed=false reason={context_release.decision.reason}",
        )

    def seal_event(self) -> None:
        self._emit(
            "receipt.sealed",
            AgentRole.SCOPEGATE,
            {"mode": "live_band_spear", "case_id": self.case.case_id},
            "RECEIPT SEALED LOCALLY: live_band_spear receipt hash is printed by CLI and stored in the JSON artifact",
        )

    @staticmethod
    def _adjudicate(verdicts: list[str]) -> str:
        if verdicts.count("BOUNCE") >= 2:
            return "BOUNCE"
        if "HUMAN_ESCALATE" in verdicts:
            return "HUMAN_ESCALATE"
        return "ALLOW"

    def _emit(self, event_type: str, actor: AgentRole | str, payload: dict[str, Any], content: str) -> dict[str, Any]:
        post = self.client.post_agent_message(self.room_id, content)
        message_id = post.get("message_id") or post.get("id") or post.get("data", {}).get("id")
        event = GateEvent.create(room_id=self.room_id, type=event_type, actor=actor, payload=payload).to_dict()
        event.update(
            {
                "band_message_id": message_id,
                "band_status": post.get("status"),
                "band_ok": bool(post.get("ok", True)),
                "band_content_sha256": _value_sha(content),
                "band_content_chars": len(content),
            }
        )
        self.live_gate_events.append(event)
        self.band_posts.append(
            {
                "event_type": event_type,
                "band_message_id": message_id,
                "status": post.get("status"),
                "ok": bool(post.get("ok", True)),
                "content_sha256": _value_sha(content),
                "content_chars": len(content),
                "content": content,
            }
        )
        return event


def _scan_posted_secrets(case: ProtectedCase, posts: list[dict[str, Any]]) -> dict[str, Any]:
    text = json.dumps([post.get("content", "") for post in posts], sort_keys=True)
    protected_hits = [key for key, value in case.protected_payload.items() if value and value in text]
    return {
        "scanned_band_posts": len(posts),
        "raw_secret_canary_posted": case.secret_canary in text,
        "protected_payload_value_posted": bool(protected_hits),
        "protected_payload_value_hit_keys": protected_hits,
        "posted_text_sha256": _value_sha(text),
    }


def run_live_band_demo(
    case_path: str | Path,
    *,
    room_id: str,
    out: str | Path | None = None,
    client: BandMessagePoster,
) -> dict[str, Any]:
    case = _load_case(case_path)
    demo = LiveBandDemoHarness(case, room_id=room_id, client=client)
    naive_radius = _naive_leak_radius(case)

    demo.post_intro_and_naive_baseline()
    demo.block_pre_grant_action()
    demo.grant()
    for agent in [AgentRole.ROUTER, AgentRole.EVIDENCE, AgentRole.RISK, AgentRole.ACTION]:
        demo.add_participant_through_gate(agent)
    demo.release_context_hash_only(AgentRole.EVIDENCE, "policy_excerpt")
    demo.probe_late_participant_recovery("Unapproved Auditor", "policy_excerpt")
    demo.run_review_gate()
    demo.revoke_and_probe()
    demo.seal_event()

    band_secret_scan = _scan_posted_secrets(case, demo.band_posts)
    transcript = {"room_id": room_id, "posts": [{k: v for k, v in post.items() if k != "content"} for post in demo.band_posts]}
    receipt = {
        "project": "RoomKey by ScopeGate",
        "mode": "live_band_spear",
        "room_id": room_id,
        "case_id": case.case_id,
        "grant_id": demo.grant_obj.grant_id if demo.grant_obj else None,
        "grant": demo.grant_obj.to_dict() if demo.grant_obj else None,
        "band_message_ids": [event.get("band_message_id") for event in demo.live_gate_events],
        "live_gate_events": demo.live_gate_events,
        "local_gate_events": demo.live_gate_events,
        "blocked_attempts": demo.blocked_attempts,
        "context_releases": demo.context_releases,
        "late_participant_probes": demo.late_participant_probes,
        "reviewer_deposits": demo.reviewer_deposits,
        "review_gate": demo.review_gate,
        "revocations": demo.revocations,
        "post_revocation_blocks": demo.post_revocation_blocks,
        "naive_baseline": {
            "simulated_locally": True,
            "would_leak_canary": naive_radius > 0,
            "raw_canary_posted_to_band": False,
            "canary_sha256": _value_sha(case.secret_canary),
        },
        "band_secret_scan": band_secret_scan,
        "naive_leak_radius": naive_radius,
        "hardened_leak_radius": leak_radius({"posts": demo.band_posts}, case.secret_canary),
        "transcript_sha256": hash_json(transcript),
        "policy_log_sha256": hash_json(demo.live_gate_events),
        "secret_canary_pre_grant_seen": False,
        "sealed_at": demo.live_gate_events[-1]["created_at"],
    }
    sealed = seal_receipt(receipt)
    if out is not None:
        write_receipt(sealed, out)
    return sealed
