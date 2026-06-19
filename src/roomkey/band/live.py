from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class MissingBandCredentials(RuntimeError):
    pass


class BandAPIError(RuntimeError):
    pass


@dataclass
class LiveBandClient:
    rest_url: str
    api_key: str = field(repr=False)
    agent_id: str | None = None
    agent_handle: str | None = None
    default_mention: dict[str, str] | None = None
    timeout_seconds: int = 30

    def redacted_config(self) -> dict[str, Any]:
        return {
            "rest_url": self.rest_url,
            "api_key": "[redacted]",
            "agent_id": self.agent_id,
            "agent_handle": self.agent_handle,
            "default_mention": self.default_mention,
        }

    def get_agent_me(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/agent/me")

    def list_agent_chats(self) -> dict[str, Any]:
        return self._request_json("GET", "/api/v1/agent/chats")

    def list_participants(self, chat_id: str) -> dict[str, Any]:
        return self._request_json("GET", f"/api/v1/agent/chats/{chat_id}/participants")

    def resolve_default_mention(self, chat_id: str) -> dict[str, str]:
        if self.default_mention:
            return dict(self.default_mention)
        participants = _response_data(self.list_participants(chat_id))
        if isinstance(participants, dict):
            participants = participants.get("participants") or participants.get("data") or []
        for participant in participants or []:
            if str(participant.get("type", "")).lower() == "user":
                mention = {
                    "id": str(participant["id"]),
                    "handle": str(participant.get("handle") or participant.get("name") or participant["id"]),
                    "name": str(participant.get("name") or participant.get("handle") or participant["id"]),
                }
                self.default_mention = mention
                return mention
        raise BandAPIError("could not resolve a human Band participant to mention")

    def post_agent_message(self, room_id: str, content: str) -> dict[str, Any]:
        mention = self.resolve_default_mention(room_id)
        payload_content = content
        mention_prefix = f"@[[{mention['id']}]]"
        if not payload_content.startswith(mention_prefix):
            payload_content = f"{mention_prefix} {payload_content}"
        payload = {"message": {"content": payload_content, "mentions": [mention]}}
        result = self._request_json("POST", f"/api/v1/agent/chats/{room_id}/messages", payload)
        data = _response_data(result)
        message_id = None
        if isinstance(data, dict):
            message_id = data.get("id") or data.get("message_id")
        if not result.get("ok"):
            raise BandAPIError(f"Band message post failed with status {result.get('status')}")
        if not message_id:
            raise BandAPIError("Band message post succeeded without returning a message id")
        return {
            "ok": True,
            "status": result.get("status"),
            "message_id": message_id,
            "content": payload_content,
            "body": result.get("body"),
        }

    def _headers(self) -> dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "curl/8.5.0",
        }

    def _request_json(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.rest_url.rstrip("/") + path
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                parsed = json.loads(raw) if raw else {}
                return {"ok": 200 <= response.status < 300, "status": response.status, "body": parsed}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            return {"ok": False, "status": exc.code, "body": parsed}


def _response_data(result: dict[str, Any]) -> Any:
    body = result.get("body")
    if isinstance(body, dict) and "data" in body:
        return body["data"]
    return body


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            values[key] = value
    return values


def _merged_band_env() -> dict[str, str]:
    credential_file = Path(os.getenv("BAND_CREDENTIAL_FILE", "/home/exor/.config/band/credentials"))
    values = _read_env_file(credential_file)
    for key, value in os.environ.items():
        if key.startswith("BAND_") or key.startswith("THENVOI_"):
            values[key] = value
    return values


def load_live_band_client_from_env() -> LiveBandClient:
    values = _merged_band_env()
    rest_url = values.get("BAND_REST_URL") or values.get("THENVOI_BASE_URL")
    api_key = values.get("BAND_AGENT_API_KEY") or values.get("BAND_API_KEY") or values.get("THENVOI_AGENT_KEY")
    agent_id = values.get("BAND_AGENT_ID")
    agent_handle = values.get("BAND_AGENT_HANDLE")
    default_mention = None
    if values.get("BAND_DEFAULT_MENTION_ID"):
        default_mention = {
            "id": values["BAND_DEFAULT_MENTION_ID"],
            "handle": values.get("BAND_DEFAULT_MENTION_HANDLE", values["BAND_DEFAULT_MENTION_ID"]),
            "name": values.get("BAND_DEFAULT_MENTION_NAME", values.get("BAND_DEFAULT_MENTION_HANDLE", values["BAND_DEFAULT_MENTION_ID"])),
        }
    if not rest_url or not api_key:
        raise MissingBandCredentials(
            "BAND_REST_URL plus BAND_AGENT_API_KEY/BAND_API_KEY are required for live Band calls"
        )
    return LiveBandClient(rest_url=rest_url, api_key=api_key, agent_id=agent_id, agent_handle=agent_handle, default_mention=default_mention)
