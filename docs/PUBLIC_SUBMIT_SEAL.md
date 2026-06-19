# Public submit seal

Status: consent-visual and lablab-assets deployment prepared for the public RoomKey evidence console, with judge-readable product flow plus machine-verifiable receipts.

```text
public_github_url=https://github.com/davfd/ScopeGateRoomKey
public_app_url=https://davfd.github.io/ScopeGateRoomKey/
public_app_fallback_url=https://cdn.jsdelivr.net/gh/davfd/ScopeGateRoomKey@main/site/index.html
public_publish_status=CONSENT_VISUAL_AND_SUBMISSION_ASSETS_DEPLOYED_READBACK_REQUIRED
public_refs_to_check=refs/heads/main,refs/heads/gh-pages
single_commit_public_history_required=true
local_hardening_branch=hardening/redteam-findings
submit_check=PASS_LOCAL
integrity_check=PASS_LOCAL
secret_scan=PASS
banned_claims=PASS
site_check=PASS
browser_verifier_contract_check=PASS
canonical_receipt_sha256=b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925
live_receipt_file_sha256=f6d2d843c7523212797a1237675a3592c477c754d0af905df767ea3005fa3b81
seal_post_message_id=3a602d9e-2411-4fb4-944f-0fa094e6df71
visible_consent_strip=Blocked -> Grant Scope -> Scoped collaboration -> Revoke -> Revoked + Sealed
submission_packet=docs/LABLAB_SUBMISSION_PACKET.md
cover_image=media/lablab-cover-16x9.png
slide_deck=docs/lablab-roomkey-slide-deck.pdf
video_status=SCRIPT_READY_MP4_OR_UPLOAD_STILL_REQUIRED
ibm_bob_status=ONLY_IF_HACKATHON_REQUIRES_IT_DO_NOT_FABRICATE
claim_boundary=receipt-pinned prototype run only; not production security or independent Band-side security
last_public_seal_update_utc=2026-06-19T06:00:30Z
```

Final exact commit SHA, CI run IDs, Pages action, and browser readback belong in the external deploy receipt produced after push, because hard-coding a final commit SHA inside a one-commit in-repo seal would change the commit it tries to name.
