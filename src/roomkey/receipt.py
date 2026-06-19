from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from roomkey.models import to_jsonable


class ReceiptVerificationError(RuntimeError):
    pass


def canonical_json(data: Any) -> str:
    return json.dumps(to_jsonable(data), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_json(data: Any) -> str:
    return sha256(canonical_json(data).encode("utf-8")).hexdigest()


def receipt_hash_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    payload = copy.deepcopy(receipt)
    payload.pop("receipt_sha256", None)
    return payload


def seal_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    sealed = copy.deepcopy(receipt)
    sealed["receipt_sha256"] = hash_json(receipt_hash_payload(sealed))
    return sealed


def write_receipt(receipt: dict[str, Any], out: str | Path) -> dict[str, Any]:
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
    return receipt


def verify_receipt(path_or_data: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(path_or_data, dict):
        receipt = copy.deepcopy(path_or_data)
    else:
        receipt = json.loads(Path(path_or_data).read_text(encoding="utf-8"))

    expected_hash = receipt.get("receipt_sha256")
    actual_hash = hash_json(receipt_hash_payload(receipt))
    if expected_hash != actual_hash:
        raise ReceiptVerificationError(f"receipt hash mismatch: expected {expected_hash}, got {actual_hash}")
    if receipt.get("secret_canary_pre_grant_seen") is not False:
        raise ReceiptVerificationError("secret canary appeared before grant")
    if receipt.get("naive_leak_radius", 0) <= 0:
        raise ReceiptVerificationError("naive leak baseline missing")
    if receipt.get("hardened_leak_radius") != 0:
        raise ReceiptVerificationError("hardened transcript leaked protected canary")
    if not receipt.get("blocked_attempts"):
        raise ReceiptVerificationError("missing blocked attempt")
    if not receipt.get("context_releases"):
        raise ReceiptVerificationError("missing scoped context release")
    probes = receipt.get("late_participant_probes") or []
    if not probes:
        raise ReceiptVerificationError("missing late/disallowed participant probe")
    if any(probe.get("recovered") for probe in probes):
        raise ReceiptVerificationError("late/disallowed participant recovered protected context")
    if not receipt.get("revocations"):
        raise ReceiptVerificationError("missing revocation")
    deposits = receipt.get("reviewer_deposits") or []
    if len(deposits) != 3:
        raise ReceiptVerificationError("expected exactly 3 reviewer deposits")
    reviewers = [deposit.get("reviewer") for deposit in deposits]
    if len(set(reviewers)) != 3:
        raise ReceiptVerificationError("reviewer deposits are not independent")
    if not receipt.get("transcript_sha256") or not receipt.get("policy_log_sha256"):
        raise ReceiptVerificationError("missing transcript/policy hashes")
    events = receipt.get("local_gate_events") or receipt.get("live_gate_events") or []
    if receipt.get("policy_log_sha256") != hash_json(events):
        raise ReceiptVerificationError("policy log hash mismatch")
    if receipt.get("mode") == "live_band_spear":
        _verify_live_band_receipt(receipt)
    _verify_event_order(events)
    return receipt


def _verify_live_band_receipt(receipt: dict[str, Any]) -> None:
    events = receipt.get("live_gate_events") or []
    if not events:
        raise ReceiptVerificationError("missing live Band gate events")
    for event in events:
        if not event.get("band_message_id"):
            raise ReceiptVerificationError("missing Band message id on live event")
        if event.get("band_ok") is not True:
            raise ReceiptVerificationError("live Band post was not acknowledged")
        if not event.get("band_content_sha256"):
            raise ReceiptVerificationError("missing Band content hash on live event")
    message_ids = receipt.get("band_message_ids") or []
    if len(message_ids) != len(events) or any(not message_id for message_id in message_ids):
        raise ReceiptVerificationError("missing Band message id list")
    scan = receipt.get("band_secret_scan") or {}
    if scan.get("raw_secret_canary_posted") is not False:
        raise ReceiptVerificationError("raw secret canary was posted to Band")
    if scan.get("protected_payload_value_posted") is not False:
        raise ReceiptVerificationError("protected payload value was posted to Band")
    for release in receipt.get("context_releases") or []:
        if "value" in release:
            raise ReceiptVerificationError("live context release contains raw value")
        if release.get("raw_value_posted_to_band") is not False:
            raise ReceiptVerificationError("live context release posted raw value")
    if not receipt.get("post_revocation_blocks"):
        raise ReceiptVerificationError("missing post-revocation block")


def _verify_event_order(events: list[dict[str, Any]]) -> None:
    types = [event.get("type") for event in events]

    def first(event_type: str) -> int:
        try:
            return types.index(event_type)
        except ValueError as exc:
            raise ReceiptVerificationError(f"event order missing {event_type}") from exc

    def first_after(event_type: str, after_index: int) -> int:
        for index, value in enumerate(types):
            if index > after_index and value == event_type:
                return index
        raise ReceiptVerificationError(f"event order missing {event_type} after index {after_index}")

    pre_block = first("action.blocked")
    grant = first("grant.granted")
    release = first("context.released")
    replay_block = first("context.replay_blocked")
    reviewer_indices = [index for index, value in enumerate(types) if value == "reviewer.deposit"]
    if len(reviewer_indices) != 3:
        raise ReceiptVerificationError("event order violation: expected exactly three reviewer.deposit events")
    if any(index <= replay_block for index in reviewer_indices):
        raise ReceiptVerificationError("event order violation: every reviewer.deposit must follow context.replay_blocked")
    adjudicated = first("review_gate.adjudicated")
    if any(index >= adjudicated for index in reviewer_indices):
        raise ReceiptVerificationError("event order violation: every reviewer.deposit must precede review_gate.adjudicated")
    revoked = first("grant.revoked")
    post_revoke_block = first_after("action.blocked", revoked)
    sealed = first("receipt.sealed")
    expected = [
        pre_block,
        grant,
        release,
        replay_block,
        min(reviewer_indices),
        max(reviewer_indices),
        adjudicated,
        revoked,
        post_revoke_block,
        sealed,
    ]
    if expected != sorted(expected):
        raise ReceiptVerificationError(
            "event order violation: expected pre-grant block -> grant -> scoped release -> "
            "late replay block -> reviewer deposits -> adjudication -> revocation -> "
            "post-revocation block -> receipt seal"
        )
