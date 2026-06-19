# Text-injection mutation receipt

## What was tested

This receipt backs the public claim that prompt-like text in inert public evidence fields does not become authority and does not change the receipt proof roots.

## Mutation cases

| Case | Expected | Result | Root effect |
|---|---|---|---|
| Add hostile prompt-like text to inert public evidence metadata | remains inert | PASS | receipt payload hash unchanged; receipt file hash unchanged; pinned evidence hashes unchanged |
| Add hostile prompt-like text to the public winning-frame field | remains inert | PASS | receipt payload hash unchanged; receipt file hash unchanged; pinned evidence hashes unchanged |
| Add reviewer text into the receipt without resealing | fail closed | PASS | receipt payload/file hash changes; submit path rejects |
| Reseal receipt mutation without updating public roots | fail closed | PASS | public evidence remains pinned to the old roots; verifier rejects mismatch |
| Add public copy that claims more than the prototype proves | blocked | PASS | banned-claim gate exits non-zero |

## Stable hashes from the run

```text
receipt_payload_hash_before=b737b1087e8af84c23e6e3a341038735511606b391641c57a056fb3f1f543925
receipt_file_hash_before=f6d2d843c7523212797a1237675a3592c477c754d0af905df767ea3005fa3b81
prompt_probe_sha256=e9ca11ebe627100b490e21d7f53fa1d7616e4a93c75408aa68b48a7dfb86b816
overclaim_probe_sha256=4cdc596e5c0773f15d5bfda7c0c235b4a4a81abb9e29263589d6d79f2592ee38
```

## Boundary

The mutation receipt proves the local package treats these strings as data and keeps proof roots pinned. It does not prove production security or exhaustive live adversarial coverage.
