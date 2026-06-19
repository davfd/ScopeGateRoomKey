from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from roomkey.models import AgentRole, GateEvent, role_value


class InMemoryBandClient:
    """Deterministic FakeBand adapter with public vs targeted transcript views."""

    def __init__(self) -> None:
        self._rooms: dict[str, dict[str, Any]] = defaultdict(lambda: {"messages": [], "events": [], "participants": set()})

    def send_message_sync(
        self,
        room_id: str,
        mention: AgentRole | str,
        text: str,
        *,
        visible_to: list[AgentRole | str] | None = None,
    ) -> str:
        message_id = f"msg_{uuid4().hex[:12]}"
        self._rooms[room_id]["messages"].append(
            {
                "message_id": message_id,
                "room_id": room_id,
                "mention": role_value(mention),
                "text": text,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "visible_to": [role_value(item) for item in visible_to] if visible_to else None,
            }
        )
        return message_id

    async def send_message(self, room_id: str, mention: AgentRole | str, text: str) -> str:
        return self.send_message_sync(room_id, mention, text)

    def send_event_sync(self, room_id: str, event: GateEvent) -> str:
        self._rooms[room_id]["events"].append(event.to_dict())
        return event.event_id

    async def send_event(self, room_id: str, event: GateEvent) -> str:
        return self.send_event_sync(room_id, event)

    def lookup_peers_sync(self, query: str | None = None) -> list[dict[str, str]]:
        peers = [
            {"handle": role.value, "kind": "roomkey-agent"}
            for role in AgentRole
            if role not in {AgentRole.INTAKE, AgentRole.SCOPEGATE}
        ]
        if query:
            q = query.lower()
            peers = [peer for peer in peers if q in peer["handle"].lower()]
        return peers

    async def lookup_peers(self, query: str | None = None) -> list[dict]:
        return self.lookup_peers_sync(query)

    def add_participant_sync(self, room_id: str, agent: AgentRole | str) -> str:
        name = role_value(agent)
        self._rooms[room_id]["participants"].add(name)
        return f"participant_{name}"

    async def add_participant(self, room_id: str, agent: AgentRole | str) -> str:
        return self.add_participant_sync(room_id, agent)

    def remove_participant_sync(self, room_id: str, agent: AgentRole | str) -> str:
        name = role_value(agent)
        self._rooms[room_id]["participants"].discard(name)
        return f"removed_{name}"

    async def remove_participant(self, room_id: str, agent: AgentRole | str) -> str:
        return self.remove_participant_sync(room_id, agent)

    def export_transcript_sync(
        self,
        room_id: str,
        *,
        viewer: AgentRole | str | None = None,
        redact_targeted_for_public: bool = True,
    ) -> dict[str, Any]:
        viewer_name = role_value(viewer) if viewer is not None else None
        room = self._rooms[room_id]
        messages = [
            self._view_message(message, viewer_name, redact_targeted_for_public)
            for message in room["messages"]
            if self._visible(message, viewer_name) or (viewer_name is None and message.get("visible_to") and redact_targeted_for_public)
        ]
        events = [
            self._view_event(event, viewer_name, redact_targeted_for_public)
            for event in room["events"]
            if self._visible(event, viewer_name) or (viewer_name is None and event.get("visible_to") and redact_targeted_for_public)
        ]
        return {
            "room_id": room_id,
            "viewer": viewer_name or "PUBLIC_REDACTED",
            "participants": sorted(room["participants"]),
            "messages": messages,
            "events": events,
        }

    async def export_transcript(self, room_id: str) -> dict:
        return self.export_transcript_sync(room_id)

    @staticmethod
    def _visible(item: dict[str, Any], viewer_name: str | None) -> bool:
        visible_to = item.get("visible_to")
        if not visible_to:
            return True
        return viewer_name in set(visible_to)

    @staticmethod
    def _view_message(message: dict[str, Any], viewer_name: str | None, redact: bool) -> dict[str, Any]:
        data = dict(message)
        if message.get("visible_to") and viewer_name not in set(message["visible_to"]):
            if redact:
                data["text"] = "[targeted message redacted]"
            else:
                return {}
        return data

    @staticmethod
    def _view_event(event: dict[str, Any], viewer_name: str | None, redact: bool) -> dict[str, Any]:
        data = dict(event)
        if event.get("visible_to") and viewer_name not in set(event["visible_to"]):
            if redact:
                data["payload"] = {"redacted": True}
            else:
                return {}
        return data
