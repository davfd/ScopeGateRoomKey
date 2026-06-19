from __future__ import annotations

import json

from roomkey import cli
from roomkey.receipt import verify_receipt


class RecordingBandClient:
    def __init__(self) -> None:
        self._seq = 0

    def post_agent_message(self, room_id: str, content: str) -> dict:
        self._seq += 1
        return {"ok": True, "status": 201, "message_id": f"band_msg_{self._seq:03d}", "content": content}


def test_band_demo_cli_writes_and_verifies_live_receipt(monkeypatch, sample_case_path, tmp_path, capsys):
    client = RecordingBandClient()
    monkeypatch.setattr(cli, "load_live_band_client_from_env", lambda: client)
    out = tmp_path / "live-band-demo.json"

    exit_code = cli.main(["band", "demo", "--room", "band-room-123", "--case", str(sample_case_path), "--out", str(out)])

    captured = capsys.readouterr()
    receipt = verify_receipt(out)
    assert exit_code == 0
    assert "PASS_LIVE_BAND_SPEAR" in captured.out
    assert f"receipt_sha256={receipt['receipt_sha256']}" in captured.out
    assert json.loads(out.read_text(encoding="utf-8"))["mode"] == "live_band_spear"
