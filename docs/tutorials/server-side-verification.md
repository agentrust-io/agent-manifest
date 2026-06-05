# Server-side manifest verification

This tutorial covers the **relying-party side**: the service that receives requests from agents and needs to decide whether to trust them. After completing it you will be able to:

- Verify an agent manifest programmatically in any Python service
- Mount a FastAPI verification router that exposes `/verify` and `/revocation-status` endpoints
- Gate requests with HTTP middleware using the manifest result
- Understand every field of `VerificationResult` and what to act on

## Prerequisites

```bash
pip install "agent-manifest[server]"
```

This installs the SDK plus FastAPI and its dependencies.

## How verification works

The verifier checks six things in order, stopping at the first failure:

1. **Revocation** — is this manifest ID in the revocation list?
2. **Expiry** — is `expires_at` in the past?
3. **Artifact hashes** — do the hashes in the manifest match what is actually running?
4. **Delegation chain** — is every hop in the chain signed by its parent?
5. **HITL record** — if human approval was required, is a valid one present?
6. **Attestation** — if `enforce_attestation=True`, was hardware attestation verified?

The result is a `VerificationResult` with an `OverallResult` enum and per-field detail.

---

## Pattern 1: Programmatic verification

Use this when you control the call site and want to act on the result in code.

```python
import json
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

# Build once at startup — share across requests
revocation_store = RevocationStore()

def check_agent(manifest_path: str) -> None:
    with open(manifest_path) as f:
        manifest = json.load(f)

    ctx = VerificationContext()          # default: no enforcement overrides
    result = verify_manifest(manifest, ctx, revocation_store)

    if result.result == OverallResult.VALID:
        print(f"[VALID] {result.manifest_id} verified at {result.verified_at}")
    elif result.result == OverallResult.REVOKED:
        raise PermissionError(f"Manifest {result.manifest_id} has been revoked")
    elif result.result == OverallResult.EXPIRED:
        raise PermissionError("Manifest has expired — agent must re-issue")
    elif result.result == OverallResult.MISMATCH:
        # Show which artifacts have drifted
        for d in result.mismatch_details:
            print(f"  [MISMATCH] {d.field}: expected {d.expected_hash}, got {d.actual_hash}")
        raise PermissionError("Artifact integrity check failed")
    else:
        raise PermissionError(f"Verification failed: {result.result}")
```

### Supplying runtime artifact hashes

If you have access to the agent's running artifacts, pass them in `VerificationContext`. The verifier compares these against the hashes in the manifest.

```python
import hashlib

with open("system_prompt.txt") as f:
    prompt_text = f.read()

ctx = VerificationContext(
    system_prompt_hash="sha256:" + hashlib.sha256(prompt_text.encode()).hexdigest(),
    model_version="gpt-4o-2024-08-06",   # or a content hash for local models
    tool_catalog_hash="sha256:e3b0c44...",
)
result = verify_manifest(manifest, ctx, revocation_store)
```

Fields that are `None` in the context are skipped — `FieldResult.NOT_BOUND` is returned for them, not a mismatch.

### Enforcement flags

```python
ctx = VerificationContext(
    enforce_hitl=True,         # MISMATCH if hitl_record is required but missing
    enforce_attestation=True,  # ATTESTATION_UNAVAILABLE if no hardware attestation
    min_slsa_level=2,          # reserved for future SLSA gate
)
```

---

## Pattern 2: FastAPI router

Use this when you want to expose verification as an HTTP service — for example, a sidecar that other services can query.

```python
from fastapi import FastAPI
from agent_manifest._verify import RevocationStore, create_router

# Load manifests from your store at startup
manifest_store: dict[str, dict] = {}

with open("kyc-agent-manifest.json") as f:
    import json
    m = json.load(f)
    manifest_store[m["manifest_id"]] = m

revocation_store = RevocationStore()

app = FastAPI()
app.include_router(create_router(manifest_store, revocation_store), prefix="/agent")
```

This mounts two endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/agent/verify?manifest_id=<id>` | Returns a `VerificationResult` |
| `GET` | `/agent/revocation-status?manifest_id=<id>` | Returns the revocation record or 404 |

**Verify a manifest:**

```bash
curl "http://localhost:8000/agent/verify?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
```

```json
{
  "verification_id": "a1b2c3d4-...",
  "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
  "verified_at": "2026-06-05T12:00:00Z",
  "result": "VALID",
  "attestation_verified": false,
  "fields_verified": {
    "system_prompt": "NOT_BOUND",
    "policy_bundle": "NOT_BOUND",
    "tool_manifest": "NOT_BOUND",
    "model_identity": "NOT_BOUND",
    "rag_corpus": "NOT_BOUND",
    "memory_baseline": "NOT_BOUND",
    "decision_trace": "NOT_BOUND",
    "supply_chain": "NOT_BOUND",
    "delegation_chain": "NOT_PRESENT",
    "hitl_record": "NOT_REQUIRED"
  },
  "mismatch_details": [],
  "evidence_pack": null,
  "verification_signature": null
}
```

**Enforce HITL and attestation via query params:**

```bash
curl "http://localhost:8000/agent/verify?manifest_id=<id>&enforce_hitl=true&enforce_attestation=true"
```

---

## Pattern 3: HTTP middleware

Use this to gate every inbound request — the agent attaches its manifest ID in a header and the middleware verifies it before routing to your handler.

```python
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

app = FastAPI()
manifest_store: dict[str, dict] = {}
revocation_store = RevocationStore()

MANIFEST_ID_HEADER = "x-agent-manifest-id"

@app.middleware("http")
async def verify_agent_manifest(request: Request, call_next):
    manifest_id = request.headers.get(MANIFEST_ID_HEADER)
    if manifest_id:
        manifest = manifest_store.get(manifest_id)
        if manifest is None:
            return JSONResponse(
                status_code=403,
                content={"detail": f"Unknown manifest: {manifest_id}"},
            )
        ctx = VerificationContext()
        result = verify_manifest(manifest, ctx, revocation_store)
        if result.result != OverallResult.VALID:
            return JSONResponse(
                status_code=403,
                content={"detail": result.result, "mismatch_details": [
                    d.model_dump() for d in result.mismatch_details
                ]},
            )
    return await call_next(request)

@app.post("/execute")
async def execute(request: Request):
    # Reaches here only if the manifest verified — or no manifest was provided
    return {"status": "ok"}
```

---

## Reading the VerificationResult

| Field | Type | Meaning |
|-------|------|---------|
| `result` | `OverallResult` | Top-level verdict — see table below |
| `attestation_verified` | `bool` | `True` if hardware attestation was confirmed |
| `fields_verified` | `FieldsVerified` | Per-artifact status (MATCH / MISMATCH / NOT_BOUND / EXPIRED) |
| `mismatch_details` | `list[MismatchDetail]` | One entry per failed artifact, with expected and actual hashes |
| `evidence_pack` | `EvidencePack` | Signed evidence bundle (populated in future releases) |
| `verification_id` | `str` | UUID for this specific verification event — use in audit logs |

**OverallResult values:**

| Value | Meaning | Action |
|-------|---------|--------|
| `VALID` | All checks passed | Allow the request |
| `REVOKED` | Manifest is in the revocation list | Block immediately — possible incident |
| `EXPIRED` | `expires_at` is in the past | Block — agent must re-issue manifest |
| `MISMATCH` | One or more artifact hashes differ | Block — agent may have drifted or been tampered |
| `ATTESTATION_UNAVAILABLE` | `enforce_attestation` was set but no attestation present | Block in prod, warn in dev |
| `INCOMPLETE` | Required fields are missing from the manifest | Block |
| `INCOMPATIBLE_VERSION` | Manifest spec version not supported | Upgrade the SDK |

---

## Running the complete example

```bash
# Terminal 1 — start the verification service
uvicorn myservice:app --reload

# Terminal 2 — verify a manifest
curl "http://localhost:8000/agent/verify?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

# Check revocation status
curl "http://localhost:8000/agent/revocation-status?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
# 404 if not revoked
```

---

## What's next

- [Tutorial: A2A delegation chains](delegation-chains.md) — verify multi-hop delegation manifests
- [Tutorial: Revocation and key rotation](revocation.md) — revoke a manifest and update the CRL
- [Tutorial: Deploying the verification endpoint](deploy-verifier.md) — containerize and run in production
