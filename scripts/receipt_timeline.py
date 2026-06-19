#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def yes_no(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return 'none'
    return str(value)


def short(value: str | None, left: int = 10, right: int = 8) -> str:
    if not value:
        return 'none'
    if len(value) <= left + right + 1:
        return value
    return f'{value[:left]}…{value[-right:]}'


def line_for_event(index: int, event: dict[str, Any]) -> str:
    typ = event.get('type')
    payload = event.get('payload') or {}
    band_message_id = event.get('band_message_id', 'none')
    band_hash = short(event.get('band_content_sha256'))
    prefix = f'{index:02d}'

    if typ == 'demo.started':
        return f'{prefix} demo STARTED case_id={payload.get("case_id")} mode={payload.get("mode")} raw_protected_payload_posted={yes_no(payload.get("raw_protected_payload_posted"))} band_message_id={band_message_id}'
    if typ == 'naive.baseline':
        return f'{prefix} naive baseline would_leak_canary={yes_no(payload.get("would_leak_canary"))} raw_canary_posted_to_band={yes_no(payload.get("raw_canary_posted_to_band"))} canary_sha256={short(payload.get("canary_sha256"))} band_message_id={band_message_id}'
    if typ == 'action.blocked':
        decision = payload.get('decision') or {}
        phase = payload.get('phase') or 'unknown'
        label = 'pre-grant BLOCK' if phase == 'pre_grant' else 'post-revocation BLOCK'
        return f'{prefix} {label} action={payload.get("action_kind")} reason={decision.get("reason")} state={decision.get("state")} band_message_id={band_message_id}'
    if typ == 'grant.requested':
        return f'{prefix} grant REQUESTED case_id={payload.get("case_id")} agents={len(payload.get("requested_agents") or [])} context_keys={len(payload.get("requested_context_keys") or [])} band_message_id={band_message_id}'
    if typ == 'grant.granted':
        return f'{prefix} human grant GRANTED grant_id={payload.get("grant_id")} agents={len(payload.get("allowed_agents") or [])} context_keys={len(payload.get("allowed_context_keys") or [])} actions={len(payload.get("allowed_action_kinds") or [])} expires_at={payload.get("expires_at")} band_message_id={band_message_id}'
    if typ == 'participant.added':
        decision = payload.get('decision') or {}
        return f'{prefix} participant ADDED agent={payload.get("agent")} reason={decision.get("reason")} band_mutation={yes_no(payload.get("band_participant_mutation"))} band_message_id={band_message_id}'
    if typ == 'context.released':
        return f'{prefix} context RELEASED key={payload.get("context_key")} raw_posted={yes_no(payload.get("raw_value_posted_to_band"))} chars={payload.get("value_chars")} sha256={short(payload.get("value_sha256"))} band_message_id={band_message_id}'
    if typ == 'context.replay_blocked':
        decision = payload.get('decision') or {}
        return f'{prefix} late replay BLOCKED participant={payload.get("participant")} recovered={yes_no(payload.get("recovered"))} release_allowed={yes_no(payload.get("release_allowed"))} reason={decision.get("reason")} visible_history_sha256={short(payload.get("visible_history_text_sha256"))} band_message_id={band_message_id}'
    if typ == 'reviewer.deposit':
        return f'{prefix} reviewer DEPOSIT reviewer={payload.get("reviewer")} verdict={payload.get("verdict")} independent={yes_no(payload.get("independent"))} raw_posted={yes_no(payload.get("raw_value_posted_to_band"))} context_keys={len(payload.get("received_context_keys") or [])} context_sha256={short(payload.get("context_value_sha256"))} band_message_id={band_message_id}'
    if typ == 'review_gate.adjudicated':
        return f'{prefix} review gate ADJUDICATED outcome={payload.get("final_outcome")} reviewers={payload.get("reviewer_count")} threshold={payload.get("threshold_rule")} band_message_id={band_message_id}'
    if typ == 'grant.revoked':
        return f'{prefix} grant REVOKED grant_id={payload.get("grant_id")} reason={payload.get("reason")} actor={payload.get("actor")} band_message_id={band_message_id}'
    if typ == 'context.blocked':
        decision = payload.get('decision') or {}
        return f'{prefix} context BLOCKED key={payload.get("context_key")} reason={decision.get("reason")} state={decision.get("state")} band_message_id={band_message_id}'
    if typ == 'receipt.sealed':
        return f'{prefix} receipt SEALED receipt_sha256={{receipt_sha256}} transcript_sha256={{transcript_sha256}} policy_log_sha256={{policy_log_sha256}} band_message_id={band_message_id} band_content_sha256={band_hash}'
    return f'{prefix} {typ} actor={event.get("actor")} band_message_id={band_message_id}'


def build_timeline(receipt: dict[str, Any]) -> list[str]:
    lines = [
        'PASS_RECEIPT_TIMELINE',
        f'project={receipt.get("project")}',
        f'case_id={receipt.get("case_id")}',
        f'mode={receipt.get("mode")}',
        f'room_id={receipt.get("room_id")}',
        f'grant_id={receipt.get("grant_id")}',
        f'band_messages={len(receipt.get("band_message_ids") or [])}',
        f'live_gate_events={len(receipt.get("live_gate_events") or [])}',
        f'context_releases={len(receipt.get("context_releases") or [])}',
        f'reviewer_deposits={len(receipt.get("reviewer_deposits") or [])}',
        f'post_revocation_blocks={len(receipt.get("post_revocation_blocks") or [])}',
        '',
        'WORKFLOW',
    ]
    for index, event in enumerate(receipt.get('live_gate_events') or [], 1):
        rendered = line_for_event(index, event).format(
            receipt_sha256=receipt.get('receipt_sha256'),
            transcript_sha256=receipt.get('transcript_sha256'),
            policy_log_sha256=receipt.get('policy_log_sha256'),
        )
        lines.append(rendered)

    scan = receipt.get('band_secret_scan') or {}
    late_replay_recovered = any(probe.get('recovered') for probe in receipt.get('late_participant_probes') or [])
    lines.extend([
        '',
        'SUMMARY',
        f'protected_payload_value_posted={yes_no(scan.get("protected_payload_value_posted"))}',
        f'raw_secret_canary_posted={yes_no(scan.get("raw_secret_canary_posted"))}',
        f'late_replay_recovered={yes_no(late_replay_recovered)}',
        f'receipt_sha256={receipt.get("receipt_sha256")}',
        f'transcript_sha256={receipt.get("transcript_sha256")}',
        f'policy_log_sha256={receipt.get("policy_log_sha256")}',
    ])
    return lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print('usage: receipt_timeline.py receipts/live-band-demo-20260618T185330Z.json', file=sys.stderr)
        return 2
    receipt_path = Path(argv[1])
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    print('\n'.join(build_timeline(receipt)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
