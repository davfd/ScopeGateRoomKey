from __future__ import annotations

from roomkey.band.live import LiveBandClient, load_live_band_client_from_env


def test_live_band_loads_agent_credentials_from_file(monkeypatch, tmp_path):
    credential_file = tmp_path / "credentials"
    credential_file.write_text(
        "BAND_REST_URL=https://app.band.ai\n"
        "BAND_AGENT_API_KEY=[REDACTED_TEST_AGENT_KEY]\n"
        "BAND_AGENT_ID=agent-123\n"
        "BAND_AGENT_HANDLE=owner/roomkey\n",
        encoding="utf-8",
    )
    for name in ["BAND_REST_URL", "BAND_API_KEY", "BAND_AGENT_API_KEY", "BAND_CREDENTIAL_FILE"]:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BAND_CREDENTIAL_FILE", str(credential_file))

    client = load_live_band_client_from_env()

    assert client.rest_url == "https://app.band.ai"
    assert client.agent_id == "agent-123"
    assert client.agent_handle == "owner/roomkey"
    assert client.redacted_config()["api_key"] == "[redacted]"


def test_live_band_request_headers_use_band_api_key_not_bearer():
    client = LiveBandClient(rest_url="https://app.band.ai", api_key="secret")

    headers = client._headers()

    assert headers["X-API-Key"] == "secret"
    assert "Authorization" not in headers
    assert headers["User-Agent"].startswith("curl/")


def test_live_band_post_agent_message_uses_nested_message_schema(monkeypatch):
    client = LiveBandClient(
        rest_url="https://app.band.ai",
        api_key="secret",
        default_mention={"id": "user-1", "handle": "owner", "name": "Owner"},
    )
    calls = []

    def fake_request(method, path, body=None):
        calls.append({"method": method, "path": path, "body": body})
        return {"ok": True, "status": 201, "body": {"data": {"id": "msg-123", "success": True}}}

    monkeypatch.setattr(client, "_request_json", fake_request)

    result = client.post_agent_message("chat-123", "ROOMKEY event")

    assert result["message_id"] == "msg-123"
    assert calls == [
        {
            "method": "POST",
            "path": "/api/v1/agent/chats/chat-123/messages",
            "body": {
                "message": {
                    "content": "@[[user-1]] ROOMKEY event",
                    "mentions": [{"id": "user-1", "handle": "owner", "name": "Owner"}],
                }
            },
        }
    ]
