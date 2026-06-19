from __future__ import annotations

import json

import pytest

from roomkey.live_demo import run_live_band_demo
from roomkey.receipt import ReceiptVerificationError, hash_json, seal_receipt, verify_receipt


class RecordingBandClient:
    def __init__(self) -> None:
        self.posts: list[dict] = []
        self._seq = 0

    def post_agent_message(self, room_id: str, content: str) -> dict:
        self._seq += 1
        message_id = f"band_msg_{self._seq:03d}"
        self.posts.append({"room_id": room_id, "content": content, "message_id": message_id})
        return {"ok": True, "status": 201, "message_id": message_id, "content": content}


def _posted_text(client: RecordingBandClient) -> str:
    return "\n".join(post["content"] for post in client.posts)


def test_live_band_demo_receipt_verifies_without_raw_secret_in_band_messages(sample_case_path, sample_case_dict, tmp_path):
    client = RecordingBandClient()
    out = tmp_path / "live-band-demo.json"

    receipt = run_live_band_demo(sample_case_path, room_id="band-room-123", out=out, client=client)
    verified = verify_receipt(out)

    posted_text = _posted_text(client)
    assert verified["receipt_sha256"] == receipt["receipt_sha256"]
    assert receipt["mode"] == "live_band_spear"
    assert receipt["band_secret_scan"]["raw_secret_canary_posted"] is False
    assert receipt["band_secret_scan"]["protected_payload_value_posted"] is False
    assert receipt["late_participant_probes"][0]["recovered"] is False
    assert receipt["post_revocation_blocks"]
    assert len(receipt["reviewer_deposits"]) == 3
    assert all(event.get("band_message_id") for event in receipt["live_gate_events"])
    assert sample_case_dict["secret_canary"] not in posted_text
    for protected_value in sample_case_dict["protected_payload"].values():
        assert protected_value not in posted_text


def test_live_receipt_fails_if_late_replay_recovers_even_when_resealed(sample_case_path, tmp_path):
    client = RecordingBandClient()
    out = tmp_path / "live-band-demo.json"
    receipt = run_live_band_demo(sample_case_path, room_id="band-room-123", out=out, client=client)
    receipt["late_participant_probes"][0]["recovered"] = True
    resealed = seal_receipt(receipt)
    out.write_text(json.dumps(resealed, indent=2, sort_keys=True), encoding="utf-8")

    with pytest.raises(ReceiptVerificationError, match="late/disallowed participant recovered"):
        verify_receipt(out)


def test_live_receipt_requires_band_message_ids(sample_case_path, tmp_path):
    client = RecordingBandClient()
    out = tmp_path / "live-band-demo.json"
    receipt = run_live_band_demo(sample_case_path, room_id="band-room-123", out=out, client=client)
    receipt["live_gate_events"][0].pop("band_message_id")
    receipt["local_gate_events"] = receipt["live_gate_events"]
    receipt["policy_log_sha256"] = hash_json(receipt["live_gate_events"])
    resealed = seal_receipt(receipt)
    out.write_text(json.dumps(resealed, indent=2, sort_keys=True), encoding="utf-8")

    with pytest.raises(ReceiptVerificationError, match="missing Band message id"):
        verify_receipt(out)
