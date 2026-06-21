# Revocation and Key Rotation

Revocation stops a compromised or decommissioned agent in under a minute. Any holder of the revoking authority's key can revoke a manifest without the original signing key. After this tutorial you will be able to:

- Issue a signed revocation record and append it to a CRL
- Verify a revocation record's signature before trusting it
- Stand up the `.well-known` CRL endpoint with FastAPI
- Configure a verifier to check the CRL before accepting a manifest
- Execute a zero-downtime key rotation after a compromise

## Prerequisites

```bash
pip install "agent-manifest[server]"
```

---

## Why revocation matters

A manifest is signed at issue time. If the signing key is later compromised, all previously issued manifests remain technically valid - their signatures still verify. Revocation provides the out-of-band mechanism to mark those manifests as untrusted without waiting for their `expires_at` to pass.

The CRL (Certificate Revocation List) is an append-only JSON-Lines file. Each line is a `SignedRevocationRecord` - the record itself is signed by the revoking authority's key, binding the revocation to a specific manifest ID and authority identity. Verifiers query the CRL before accepting any manifest.

---

## Part 1: Revoke a manifest programmatically

```python
from agent_manifest._revocation import sign_revocation, verify_revocation_signature, FileCRL
from agent_manifest import generate_ed25519

# The revoking authority keypair - keep this separate from the signing key
revocation_kp = generate_ed25519()

# The manifest ID to revoke (UUID v7 from your manifest store)
manifest_id = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

record = sign_revocation(
    manifest_id=manifest_id,
    reason="Key compromise detected in incident-2026-06-07",
    revoked_by="spiffe://security.acme.com/incident-response",
    keypair=revocation_kp,
)

print(f"Revoked: {record.manifest_id}")
print(f"At:      {record.revoked_at}")
print(f"Sig:     {record.revocation_signature[:32]}...")
```

Or via the CLI:

```bash
manifest revoke \
  --manifest-id 018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c \
  --reason "key compromise" \
  --revoked-by security@example.com \
  --key keys/revocation-private.hex \
  --crl crl.jsonl
```

Append the record to the CRL file and verify the record's own signature before trusting it:

```python
crl = FileCRL("revocations.jsonl")
crl.revoke(record)

# Verify the revocation record's signature before trusting it
verify_revocation_signature(record, revocation_kp.public_bytes)
# Raises cryptography.exceptions.InvalidSignature if the record was tampered

assert crl.is_revoked(manifest_id)
print(f"CRL now contains {len(crl.all_records())} record(s)")
```

`FileCRL` is append-only - records are never deleted. It is suitable for development and small deployments. For production, replace it with a database-backed store and serve the CRL from there.

---

## Part 2: Stand up the CRL endpoint with FastAPI

The `.well-known/agent-manifest/revocation` endpoint lets any verifier check revocation status over HTTP without access to the CRL file directly.

```python
from fastapi import FastAPI
from agent_manifest._revocation import create_crl_router, FileCRL

app = FastAPI()
crl = FileCRL("revocations.jsonl")
app.include_router(create_crl_router(crl))

# Mounts:
# GET /.well-known/agent-manifest/revocation
#     Returns all revocation records as a JSON array
# GET /.well-known/agent-manifest/revocation/{manifest_id}
#     Returns one record, or 404 if not revoked
```

```bash
uvicorn myapp:app --reload

# Check if a manifest is revoked
curl http://localhost:8000/.well-known/agent-manifest/revocation/018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c
# 200 with the signed revocation record if revoked
# 404 with {"error_code": "NOT_REVOKED", ...} if clean
```

---

## Part 3: Configure a verifier to check the CRL

Wire `FileCRL` into a `RevocationStore` so `verify_manifest()` checks revocation on every call.

```python
import json
from agent_manifest._verify import (
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)
from agent_manifest._revocation import FileCRL

# Load the CRL once at startup
crl = FileCRL("revocations.jsonl")
store = RevocationStore()
for rec in crl.all_records():
    store.revoke(RevocationRecord(
        manifest_id=rec.manifest_id,
        revoked_at=rec.revoked_at,
        reason=rec.reason,
        revoked_by=rec.revoked_by,
    ))

# Verify a manifest against the loaded CRL
with open("manifest.json") as f:
    manifest = json.load(f)

result = verify_manifest(manifest, VerificationContext(), store)

if result.result == OverallResult.REVOKED:
    raise PermissionError(f"Manifest {result.manifest_id} is revoked")
elif result.result == OverallResult.VALID:
    print("Manifest is valid")
```

---

## Part 4: Key rotation after a compromise

Use this procedure when a signing key is compromised, expiring, or changing ownership. The goal is to revoke all manifests signed by the old key and replace them with manifests signed by a new key, with a brief overlap window to avoid dropped requests.

### Generate the new keypair

```python
from agent_manifest import generate_ed25519

new_kp = generate_ed25519()
# Store new_kp.private_b64url() securely - this is the new signing key
```

Or via CLI:

```bash
manifest keygen -d keys/new/
```

### Re-sign all active manifests with the new key

```python
import json
from pathlib import Path
from agent_manifest._signing import Ed25519Signer

signer = Ed25519Signer(new_kp)

for manifest_path in Path("manifests/").glob("*.json"):
    with open(manifest_path) as f:
        manifest = json.load(f)

    manifest.pop("signature", None)  # strip the old signature
    manifest["signature"] = signer.sign(manifest)

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
```

### Revoke every manifest signed by the old key

```python
old_manifest_ids = [
    "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "018aaaaa-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
]

for mid in old_manifest_ids:
    rec = sign_revocation(
        manifest_id=mid,
        reason="key rotation - old signing key decommissioned 2026-06-07",
        revoked_by="spiffe://security.acme.com/incident-response",
        keypair=revocation_kp,
    )
    crl.revoke(rec)
```

### Overlap window and decommission

Run both the old and new manifests in parallel for five minutes to allow any in-flight requests to drain. Once verifiers have updated their CRL cache, decommission the old private key:

```
t=0   Generate new key, begin re-signing manifests
t=2m  New manifests deployed and live
t=5m  Revoke old manifests in CRL
t=7m  All verifiers have fetched the updated CRL
t=10m Shred old private key material; audit the deletion
```

---

## End-to-end incident response example

```python
# 1. Detect: CI log exposes signing key
compromised_manifest_id = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

# 2. Revoke immediately
record = sign_revocation(
    manifest_id=compromised_manifest_id,
    reason="signing key exposed in CI log - incident-2026-06-07",
    revoked_by="spiffe://security.acme.com/incident-response",
    keypair=revocation_kp,
)
crl.revoke(record)

# 3. Confirm the old manifest is now rejected
store = RevocationStore()
store.revoke(RevocationRecord(
    manifest_id=record.manifest_id,
    revoked_at=record.revoked_at,
    reason=record.reason,
    revoked_by=record.revoked_by,
))

with open("old-manifest.json") as f:
    old_manifest = json.load(f)

result = verify_manifest(old_manifest, VerificationContext(), store)
assert result.result == OverallResult.REVOKED
print("Old manifest correctly rejected")
```

---

## Notes on `FileCRL` in production

`FileCRL` uses a file lock and an in-memory cache. It is safe for a single process on a single host. For multi-replica or multi-host deployments:

- Replace it with a database-backed store (Postgres, Redis, etc.)
- Distribute the CRL via the `.well-known` HTTP endpoint rather than sharing a file
- Set a short TTL on the HTTP response so verifiers pick up revocations quickly

---

## Summary

This tutorial covered issuing a signed revocation record, serving the CRL endpoint, wiring it into `verify_manifest()`, and executing a zero-downtime key rotation. See [Deploying the verification endpoint](deploying-the-verification-endpoint.md) to host the CRL and verify endpoints in production, and [Operations: Key rotation runbook](../operations/key-rotation.md) for the incident response runbook.
