# Firmware Manifest Format (Phase 3 contract)

Trusted reference state for companion-side integrity. Three files, same basename:

| File | Content | Bound |
|---|---|---|
| `firmware_manifest.json` | UTF-8 JSON, <= 1 MiB | read capped |
| `firmware_manifest.json.sig` | HMAC-SHA256 hex over canonical JSON (1 line) | 64 hex chars |
| `firmware_manifest.json.key` | hex-encoded HMAC key (1 line) | kept root-only (0600) |

## Manifest schema
```json
{
  "manifest_version": 1,
  "generated_utc": "2026-09-24T00:00:00Z",
  "algorithm": "sha256",
  "entries": [
    {"path": "firmware/ardupilot.apj", "sha256": "<64 hex>", "size": 12345}
  ]
}
```
Rules (violations fail LOUDLY via `ManifestError`):
- `path`: POSIX-style, **relative to the watch root**, no leading `/`, no `..`, unique.
- `size`: non-negative integer; mismatch => `size_mismatch` verdict.
- `entries`: non-empty list.

## Canonical signature
`sig = HMAC_SHA256(key, json.dumps(manifest, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("utf-8"))`
Verification is constant-time (`hmac.compare_digest`).

## Generation snippet
```python
from companion_integrity import hash_file, sign_manifest
digest, size = hash_file("firmware/ardupilot.apj")
manifest = {"manifest_version": 1, "generated_utc": "...", "algorithm": "sha256",
            "entries": [{"path": "firmware/ardupilot.apj", "sha256": digest, "size": size}]}
open("firmware_manifest.json", "w").write(json.dumps(manifest))
open("firmware_manifest.json.sig", "w").write(sign_manifest(manifest, key))
open("firmware_manifest.json.key", "w").write(key.hex())
```

## Semantics and limits
- Manifest = **expected state for THIS companion**; every entry must exist under a watch root (`companion_file_missing` otherwise).
- Verdicts: `ok | hash_mismatch | size_mismatch | missing | not_in_manifest | hash_capped_or_unreadable`.
- HMAC protects update payloads against **off-platform tampering**; it does NOT survive full companion compromise (key is on the same disk). FC-side guarantees (secure boot/TPM) are out of scope — see threat model F-011/F-012.
- Hashing is chunked, capped at 32 MiB/file, and runs in the bounded background worker — never on the MAVLink hot path.
