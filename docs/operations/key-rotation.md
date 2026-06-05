# Key rotation runbook

This runbook covers rotating a signing key in production. Run it when a key expires, is compromised, or a scheduled rotation policy triggers.

---

## When to rotate

| Trigger | Urgency | Overlap window |
|---------|---------|----------------|
| Key compromise suspected | Immediate | None — revoke old key first |
| Scheduled expiry (90-day policy) | Planned | 24-hour overlap |
| Personnel change (key holder leaves) | Same day | 1-hour overlap |
| Hardware security key replacement | Planned | 24-hour overlap |

---

## Pre-rotation checklist

Before starting:

- [ ] Identify all active manifests signed with the current key (query your manifest store by `signature.key_id`)
- [ ] Confirm the new key is generated in a secure environment (HSM or secrets manager — not on a developer workstation)
- [ ] Confirm CRL endpoint is reachable and writable
- [ ] Alert the on-call rotation so they expect a temporary spike in INVALID results during overlap

---

## Step 1 — Generate a new key pair

```bash
# Generate a new Ed25519 key pair
manifest keygen --out /path/to/new-signing-key.b64url --print-pub

# The printed public key goes into your trust anchor configuration
# The private key stays in the secrets manager — never in source control
```

Or in Python:

```python
from agent_manifest import generate_ed25519

new_kp = generate_ed25519()
print("New key_id:", new_kp.key_id)
print("Public key (base64url):", new_kp.public_b64url())
# Store new_kp.private_b64url() in your secrets manager
```

---

## Step 2 — Re-sign active manifests

Re-issue every active manifest with the new key. The `manifest_id` and `issued_at` stay the same; only the `signature` block changes.

```python
from agent_manifest._signing import Ed25519Signer, ed25519_from_private_bytes
import base64, json

# Load the new private key from the secrets manager
raw = base64.urlsafe_b64decode(new_private_key_b64url + "==")
new_kp = ed25519_from_private_bytes(raw)
signer = Ed25519Signer(new_kp)

for manifest in active_manifests:
    # Remove the old signature so the pre-image is clean
    manifest.pop("signature", None)
    # Sign with the new key
    new_sig = signer.sign(manifest)
    manifest["signature"] = new_sig
    # Write the updated manifest back to your store
    manifest_store[manifest["manifest_id"]] = manifest
```

---

## Step 3 — Revoke the old key

Issue a key-level revocation record for every manifest signed with the old key:

```python
from agent_manifest._revocation import sign_revocation, FileCRL
from pathlib import Path

crl = FileCRL(Path("crl.jsonl"))

for manifest_id in manifests_signed_with_old_key:
    record = sign_revocation(
        manifest_id=manifest_id,
        reason=f"Key rotation — old key_id={old_key_id}",
        revoked_by="spiffe://trust.acme.co/security-team",
        keypair=new_kp,   # sign revocations with the NEW key
    )
    crl.revoke(record)
```

---

## Step 4 — Update the CRL endpoint

The `FileCRL` append-only file is your CRL store. Publish it to your `.well-known` endpoint:

```bash
# If serving from a static file host (S3, GCS, Azure Blob):
aws s3 cp crl.jsonl s3://your-bucket/.well-known/agent-manifest/revocation \
  --content-type application/x-ndjson \
  --cache-control "max-age=30"

# If serving from the FastAPI CRL router, the file is already live —
# the router reads it on each request.
```

---

## Step 5 — Notify verifiers

If your verifiers use a trust anchor discovery endpoint (`/.well-known/agent-manifest/trust-anchor`), update it with the new public key:

```json
{
  "active_key_id": "sha256:<new-key-id>",
  "keys": [
    {
      "key_id": "sha256:<new-key-id>",
      "algorithm": "Ed25519",
      "public_key": "<new-public-key-base64url>",
      "valid_from": "2026-06-05T10:00:00Z"
    }
  ]
}
```

Verifiers that cache the trust anchor will pick up the new key at their next cache expiry (typically 5–60 minutes).

---

## Step 6 — Decommission the old private key

After the overlap window has closed and all verifiers have accepted at least one manifest signed with the new key:

1. Delete the old private key from the secrets manager
2. Archive the old public key (it is still needed to verify historical manifests during the retention window)
3. Record the rotation event in your audit log with timestamp and new key ID

---

## Zero-downtime overlap

During the overlap window, both the old and new keys are active. Verifiers may encounter manifests signed by either key. The correct behaviour:

- Verifiers that know both keys accept both signatures
- Verifiers that only know the new key will reject old-signed manifests — deploy new manifests before updating verifiers

Recommended sequence for zero downtime:

```
t=0    Generate new key
t=5m   Re-sign manifests, publish new trust anchor
t=30m  Wait for all verifiers to pick up new trust anchor
t=35m  Revoke old-key manifests, update CRL
t=1h   Delete old private key
```

---

## Rollback procedure

If the new key is defective (e.g., wrong algorithm, corrupted private key bytes):

1. **Do not revoke the old key** — keep it active
2. Re-sign manifests with the old key (same process as Step 2)
3. Remove the new key from the trust anchor
4. Investigate the new key generation before retrying

---

## Monitoring during rotation

Watch for these signals during and after rotation:

- `verification_requests_total{result="INVALID"}` spike → verifiers are seeing manifests signed with a key they don't recognise
- `verification_requests_total{result="REVOKED"}` spike → CRL is propagating correctly
- p99 verification latency spike → CRL endpoint is under load from the batch revocation

See [Monitoring guide](monitoring.md) for dashboard configuration.
