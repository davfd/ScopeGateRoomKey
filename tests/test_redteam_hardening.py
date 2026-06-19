from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from roomkey.context_store import ContextStore
from roomkey.models import AgentRole, GrantState, ProtectedCase, ScopedGrant
from roomkey.policy import PolicyGate
from roomkey.receipt import hash_json, seal_receipt

ROOT = Path(__file__).resolve().parents[1]
LIVE_RECEIPT = Path("receipts/live-band-demo-20260618T185330Z.json")
SITE_RECEIPT = Path("site/receipts/live-band-demo-20260618T185330Z.json")

SUBMIT_RECURSION_SKIP = pytest.mark.skipif(
    __import__("os").environ.get("ROOMKEY_SUBMIT_CHECK") == "1",
    reason="this regression invokes submit_check in a temp copy; submit_check runs integrity gates separately",
)


def _case(case_id: str, value: str) -> ProtectedCase:
    return ProtectedCase(
        case_id=case_id,
        safe_metadata={"case_type": "redteam_fixture"},
        protected_payload={"policy_excerpt": value},
        secret_canary=f"PUBLIC_SYNTHETIC_CANARY_{case_id}",
    )


def _grant(**overrides) -> ScopedGrant:
    data = {
        "case_id": "case-a",
        "room_id": "room-1",
        "grant_id": "grant-redteam",
        "purpose": "redteam fixture",
        "allowed_agents": [AgentRole.EVIDENCE],
        "allowed_context_keys": ["policy_excerpt"],
        "allowed_action_kinds": ["send_wire_review"],
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "human_approver": "operator",
        "state": GrantState.GRANT_SCOPED,
    }
    data.update(overrides)
    return ScopedGrant(**data)


def _copy_repo(tmp_path: Path) -> Path:
    dst = tmp_path / "repo"
    def ignore(dir_name: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {".git", ".venv", ".pytest_cache", "__pycache__"}}
    shutil.copytree(ROOT, dst, ignore=ignore)
    return dst


def _run_submit_check(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/submit_check.py"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def _run_site_check(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/site_check.py", "site/index.html", "site/evidence.json"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def test_grant_without_human_approver_cannot_execute_action():
    gate = PolicyGate()
    grant = _grant(human_approver=None)

    decision = gate.can_execute_action(grant, "send_wire_review", human_approved=True, case_id="case-a")

    assert decision.allowed is False
    assert "approver" in decision.reason


def test_grant_is_bound_to_case_id_and_cannot_cross_release():
    gate = PolicyGate()
    store = ContextStore.from_cases([_case("case-a", "VALUE-A"), _case("case-b", "VALUE-B")], gate=gate)
    grant = _grant(case_id="case-a")

    release = store.release_context("case-b", "policy_excerpt", grant, AgentRole.EVIDENCE)

    assert release.allowed is False
    assert release.value is None
    assert "case" in release.decision.reason


def test_revoked_grant_id_invalidates_stale_grant_references():
    gate = PolicyGate()
    store = ContextStore.from_cases([_case("case-a", "VALUE-A")], gate=gate)
    grant = _grant(case_id="case-a")
    import copy
    stale_reference = copy.deepcopy(grant)

    gate.revoke(grant, actor="operator", reason="redteam")
    release = store.release_context("case-a", "policy_excerpt", stale_reference, AgentRole.EVIDENCE)

    assert release.allowed is False
    assert release.value is None
    assert "revoked" in release.decision.reason


def test_revoked_grant_id_blocks_stale_participant_add_and_does_not_cross_cases():
    gate = PolicyGate()
    grant = _grant(case_id="case-a", room_id="room-a", grant_id="grant-same-id")
    import copy
    stale_copy = copy.deepcopy(grant)

    gate.revoke(grant, actor="operator", reason="redteam")

    assert gate.can_add_participant(stale_copy, AgentRole.EVIDENCE).allowed is False
    same_id_other_case = _grant(case_id="case-b", room_id="room-b", grant_id="grant-same-id")
    assert gate.can_release_context(same_id_other_case, AgentRole.EVIDENCE, "policy_excerpt", case_id="case-b").allowed is True


def test_revocation_registry_is_explicit_not_process_global():
    gate = PolicyGate()
    grant = _grant(case_id="case-a", room_id="room-a", grant_id="grant-order-leak")
    import copy
    stale_copy = copy.deepcopy(grant)

    gate.revoke(grant, actor="operator", reason="redteam")

    assert gate.can_release_context(stale_copy, AgentRole.EVIDENCE, "policy_excerpt", case_id="case-a").allowed is False
    fresh_gate = PolicyGate()
    fresh_same_key_grant = _grant(case_id="case-a", room_id="room-a", grant_id="grant-order-leak")
    assert fresh_gate.can_release_context(fresh_same_key_grant, AgentRole.EVIDENCE, "policy_excerpt", case_id="case-a").allowed is True


def test_policy_gate_requires_case_id_on_direct_context_and_action_checks():
    gate = PolicyGate()
    grant = _grant(case_id="case-a")

    assert gate.can_release_context(grant, AgentRole.EVIDENCE, "policy_excerpt").allowed is False
    assert gate.can_execute_action(grant, "send_wire_review", human_approved=True).allowed is False


@SUBMIT_RECURSION_SKIP
def test_resealed_forged_band_message_ids_fail_submit_check(tmp_path):
    repo = _copy_repo(tmp_path)
    for rel in [LIVE_RECEIPT, SITE_RECEIPT]:
        path = repo / rel
        receipt = json.loads(path.read_text(encoding="utf-8"))
        forged_ids = []
        for index, event in enumerate(receipt["live_gate_events"], start=1):
            forged = f"forged-message-id-{index:02d}"
            event["band_message_id"] = forged
            forged_ids.append(forged)
        receipt["local_gate_events"] = receipt["live_gate_events"]
        receipt["band_message_ids"] = forged_ids
        receipt["policy_log_sha256"] = hash_json(receipt["live_gate_events"])
        path.write_text(json.dumps(seal_receipt(receipt), indent=2, sort_keys=True), encoding="utf-8")

    proc = _run_submit_check(repo)

    assert proc.returncode != 0, proc.stdout
    assert "canonical receipt" in proc.stdout or "Band message" in proc.stdout or "hash" in proc.stdout


def test_site_receipt_copy_must_match_root_receipt(tmp_path):
    repo = _copy_repo(tmp_path)
    site_path = repo / SITE_RECEIPT
    receipt = json.loads(site_path.read_text(encoding="utf-8"))
    receipt["band_message_ids"][0] = "site-only-forged-id"
    site_path.write_text(json.dumps(seal_receipt(receipt), indent=2, sort_keys=True), encoding="utf-8")

    proc = _run_site_check(repo)

    assert proc.returncode != 0, proc.stdout
    assert "site receipt" in proc.stdout or "canonical receipt" in proc.stdout


@SUBMIT_RECURSION_SKIP
def test_invalid_schema_files_fail_submit_check(tmp_path):
    repo = _copy_repo(tmp_path)
    (repo / "receipt.schema.json").write_text("not json schema\n", encoding="utf-8")
    (repo / "public-proof.schema.json").write_text("not json schema\n", encoding="utf-8")

    proc = _run_submit_check(repo)

    assert proc.returncode != 0, proc.stdout
    assert "failed" in proc.stdout.lower() or "schema" in proc.stdout.lower()


def test_valid_but_incompatible_schema_files_fail_integrity_check(tmp_path):
    repo = _copy_repo(tmp_path)
    incompatible_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["sentinel_absent_field"],
        "properties": {"sentinel_absent_field": {"type": "string"}},
    }
    (repo / "receipt.schema.json").write_text(json.dumps(incompatible_schema), encoding="utf-8")
    (repo / "public-proof.schema.json").write_text(json.dumps(incompatible_schema), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "scripts/integrity_check.py"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert proc.returncode != 0, proc.stdout
    assert "schema validation failed" in proc.stdout


@SUBMIT_RECURSION_SKIP
def test_valid_but_incompatible_schema_files_fail_submit_check(tmp_path):
    repo = _copy_repo(tmp_path)
    incompatible_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["sentinel_absent_field"],
        "properties": {"sentinel_absent_field": {"type": "string"}},
    }
    (repo / "receipt.schema.json").write_text(json.dumps(incompatible_schema), encoding="utf-8")
    (repo / "public-proof.schema.json").write_text(json.dumps(incompatible_schema), encoding="utf-8")

    proc = _run_submit_check(repo)

    assert proc.returncode != 0, proc.stdout
    assert "schema validation failed" in proc.stdout


def test_secret_scan_rejects_raw_protected_payload_and_canary_literals(tmp_path):
    repo = _copy_repo(tmp_path)
    sample = repo / "samples" / "leaky_sensitive.json"
    sample.write_text(
        json.dumps(
            {
                "case_id": "leaky",
                "safe_metadata": {},
                "protected_payload": {"bank_account": "REALISTIC-ACCOUNT-123456789"},
                "secret_canary": "LEAK_ME_CANARY_123456789",
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [sys.executable, "scripts/secret_scan.py"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert proc.returncode != 0, proc.stdout
    assert "protected_payload" in proc.stdout or "secret_canary" in proc.stdout
