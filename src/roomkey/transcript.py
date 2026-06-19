from __future__ import annotations

import json
from typing import Any


def leak_radius(transcript: dict[str, Any], secret: str) -> int:
    return json.dumps(transcript, sort_keys=True).count(secret)


def secret_seen_before_event(transcript: dict[str, Any], secret: str, event_type: str) -> bool:
    timeline: list[dict[str, Any]] = []
    for message in transcript.get("messages", []):
        timeline.append({"kind": "message", "created_at": message.get("created_at", ""), "value": message})
    for event in transcript.get("events", []):
        timeline.append({"kind": "event", "created_at": event.get("created_at", ""), "value": event})
    for item in sorted(timeline, key=lambda row: row["created_at"]):
        value = item["value"]
        if item["kind"] == "event" and value.get("type") == event_type:
            return False
        if secret in json.dumps(value, sort_keys=True):
            return True
    return False
