# Evidence panel

RoomKey is a control layer for serious multi-agent work on Band. This evidence panel records the prototype run behind the live page: a supplier bank-change review, a blocked pre-grant request, a narrow human approval, reviewer deposits, revocation, and a sealed receipt.

```text
canonical_receipt_sha256=b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925
live_receipt_file_sha256=f6d2d843c7523212797a1237675a3592c477c754d0af905df767ea3005fa3b81
seal_post_message_id=3a602d9e-2411-4fb4-944f-0fa094e6df71
mode=live_band_spear
band_message_count=25
first_band_message_id=a70847ec-3316-4e5c-94dd-7f436fb6b095
last_receipt_event_message_id=01ef4362-69f4-49a5-81cd-f313df0cf01e
late_replay_recovered=false
raw_secret_canary_posted=false
protected_payload_value_posted=false
post_revocation_blocks=2
reviewer_deposits=3
```

Verify locally:

```bash
make submit-check
```

## Public-safe media

```text
media/evidence-console-screenshot-20260618T2056Z.png
sha256=e43bd159b1d464e22d2cbfcebf747f63b06922f2c5df6da99681fbd859183657
```
