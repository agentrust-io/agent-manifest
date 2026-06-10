# Revocation and key rotation

Revocation lets you stop a compromised or decommissioned agent in under a minute. After this tutorial you will be able to:

- Issue a signed revocation record for any manifest
- Serve a CRL (Certificate Revocation List) at the standard `.well-known` endpoint
- Configure a verifier to check the CRL before accepting a manifest
- Execute a zero-downtime key rotation

## Prerequisites

```bash
pip install "agent-manifest[server]"
```

---

## How revocation works

Revocation is separate from signing. Anyone with the **revoking authority's key** can revoke a manifest  -  it does not require the original signing key. Each revocation record is signed over `{manifest_id, revoked_at, reason, revoked_by}` to prevent forgery.

The CRL is an append-only JSON-Lines file. Each line is one `SignedRevocationRecord`. The verifier fetches or reads the CRL at verification time and rejects any manifest whose `manifest_id` appears in it.

---

## Part 1: Revoke a manifest

### Step 1: Issue the revocation

```python
from agent_manifest._revocation import sign_revocation, verify_revocation_signature, FileCRL
from agent_manifest import generate_ed25519
from pathlib import Path

# The revoking authority keypair  -  store this separately from the signing key
revocation_kp = generate_ed25519()

# The manifest ID you want to revoke (UUID v7 from your manifest)
manifest_id = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

record = sign_revocation(
    manifest_id=manifest_id,
    reason="key compromise  -  signing key leaked in CI log",
    revoked_by="security@example.com",
    keypair=revocation_kp,
)

print(f"Revoked {record.manifest_id} at {record.revoked_at}")
print(f"Signature: {record.revocation_signature[:32]}...")
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

### Step 2: Append to the CRL

```python
crl = FileCRL(Path("crl.jsonl"))
crl.revoke(record)

# Verify it was written
assert crl.is_revoked(manifest_id)
print(f"CRL now contains {len(crl.all_records())} record(s)")
```

### Step 3: Verify the revocation signature

Before trusting a CRL entry, verify its signature with the revoking authority's public key:

```python
verify_revocation_signature(record, revocation_kp.public_bytes)
# Raises cryptography.exceptions.InvalidSignature if tampered
```

---

## Part 2: Serve the CRL

Stand up the `.well-known/agent-manifest/revocation` endpoint so verifiers can query it.

```python
from fastapi import FastAPI
from agent_manifest._revocation import FileCRL, create_crl_router
from pathlib import Path

crl = FileCRL(Path("crl.jsonl"))
app = FastAPI()
app.include_router(create_crl_router(crl))
```

This mounts:

| Method | Path | Returns |
|--------|------|---------|
| `GET` | `/.well-known/agent-manifest/revocation` | All revocation records as JSON array |
| `GET` | `/.well-known/agent-manifest/revocation/{manifest_id}` | Single record, or 404 if not revoked |

```bash
# Check if a manifest is revoked
curl http://localhost:8000/.well-known/agent-manifest/revocation/018f4a3b-...
# 200 with the revocation record if revoked
# 404 with {"detail": {"error_code": "NOT_REVOKED", ...}} if clean
```

---

## Part 3: Verify against the CRL

### In-process (using FileCRL)

```python
from agent_manifest._verify import RevocationStore, VerificationContext, verify_manifest, OverallResult
from agent_manifest._revocation import FileCRL
from pathlib import Path
import json

# Load the CRL once at startup
crl = FileCRL(Path("crl.jsonl"))

# Wrap it so the verify engine can query it
store = RevocationStore()
for rec in crl.all_records():
    from agent_manifest._verify import RevocationRecord
    store.revoke(RevocationRecord(
        manifest_id=rec.manifest_id,
        revoked_at=rec.revoked_at,
        reason=rec.reason,
        revoked_by=rec.revoked_by,
    ))

with open("manifest.json") as f:
    manifest = json.load(f)

result = verify_manifest(manifest, VerificationContext(), store)

if result.result == OverallResult.REVOKED:
    print("Manifest has been revoked  -  request blocked")
elif result.result == OverallResult.VALID:
    print("Manifest is valid")
```

---

## Part 4: Key rotation

Use this procedure when a signing key is compromised, expiring, or changing ownership.

### Step 1: Generate the new keypair

```python
new_kp = generate_ed25519()
# Save new_kp.private_hex and new_kp.public_hex securely
```

Or via CLI:
```bash
manifest keygen -d keys/new/
```

### Step 2: Re-sign all active manifests with the new key

```python
import json
from agent_manifest._signing import Ed25519Signer
from pathlib import Path

signer = Ed25519Signer(new_kp)

for manifest_path in Path("manifests/").glob("*.json"):
    with open(manifest_path) as f:
        manifest = json.load(f)

    # Strip the old signature before re-signing
    manifest.pop("signature", None)
    resigned = signer.sign(manifest)

    with open(manifest_path, "w") as f:
        json.dump(resigned, f, indent=2)
```

### Step 3: Revoke every manifest signed by the old key

```python
old_key_manifests = [
    "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
    "018aaaaa-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
]

for mid in old_key_manifests:
    rec = sign_revocation(
        manifest_id=mid,
        reason="key rotation  -  old signing key decommissioned",
        revoked_by="security@example.com",
        keypair=revocation_kp,
    )
    crl.revoke(rec)
```

### Step 4: Overlap window

Verifiers that cached the old manifests will see them as revoked and request a fresh one. Run both keys in parallel for 5 minutes if you need zero downtime, then decommission the old private key.

### Step 5: Decommission the old key

Delete or shred the old private key material. Audit the deletion.

---

## Overlap timing reference

```
t=0   Generate new key, begin re-signing manifests
t=2m  New manifests deployed to agents
t=5m  Revoke old manifests in CRL
t=7m  Old key is no longer accepted by any verifier
t=10m Decommission old private key
```

---

## What's next

- [Tutorial: Deploying the verification endpoint](deploy-verifier.md)  -  host the CRL and verify endpoints in production
- [Operations: Key rotation runbook](../operations/key-rotation.md)  -  step-by-step runbook for incident response
