# Server-Side Manifest Verification

This tutorial covers the relying-party side: a service that receives requests from agents and needs to decide whether to trust them. After completing it you will be able to:

- Verify an agent manifest programmatically in any Python service
- Mount a FastAPI verification router exposing `/verify` and `/revocation-status` endpoints
- Gate requests with HTTP middleware using the manifest result
- Read every field of `VerificationResult` and know what to act on
- Configure CRL checking via `RevocationStore` or `FileCRL`

## Prerequisites

```bash
pip install "agent-manifest[server]"
```

---

## What verification checks

The verifier checks six things in order, stopping at the first hard failure:

1. **Revocation**  -  is this manifest ID in the revocation store?
2. **Expiry**  -  is `expires_at` in the past?
3. **Artifact hashes**  -  do the hashes in the manifest match what is actually running?
4. **Delegation chain**  -  is every hop signed by its parent?
5. **HITL record**  -  if approval was required, is a valid, unexpired one present?
6. **Attestation**  -  if `enforce_attestation=True`, was hardware attestation verified?

---

## Programmatic verification in middleware

Use this pattern when you control the call site and want to act on the result in application code.

```python
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

# Build once at startup, share across requests
revocation_store = RevocationStore()
ctx = VerificationContext(enforce_attestation=True, enforce_hitl=False)

result = verify_manifest(manifest_dict, ctx, revocation_store)

if result.result != OverallResult.VALID:
    raise PermissionError(f"Agent manifest invalid: {result.result}")
```

### Supplying runtime artifact hashes

Pass hashes for any artifacts you can observe at runtime. Fields left as `None` in the context are skipped and return `FieldResult.NOT_BOUND`, not a mismatch.

```python
import hashlib

with open("system_prompt.txt") as f:
    prompt_text = f.read()

ctx = VerificationContext(
    system_prompt_hash="sha256:" + hashlib.sha256(prompt_text.encode()).hexdigest(),
    model_version="claude-sonnet-4-5-20251022",
    tool_catalog_hash="sha256:e3b0c44...",
    enforce_hitl=True,
    enforce_attestation=False,
)
result = verify_manifest(manifest_dict, ctx, revocation_store)
```

---

## Mounting verification endpoints with FastAPI

Use this when you want to expose verification as an HTTP service, for example a sidecar that other services query.

```python
from fastapi import FastAPI
from agent_manifest._verify import create_router, RevocationStore

app = FastAPI()
manifest_store: dict = {}   # manifest_id -> manifest dict
revocation_store = RevocationStore()

app.include_router(create_router(manifest_store, revocation_store), prefix="/agent")

# GET /agent/verify?manifest_id=...&enforce_hitl=true
# GET /agent/revocation-status?manifest_id=...
```

**Verify a manifest:**

```bash
curl "http://localhost:8000/agent/verify?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
```

```json
{
  "verification_id": "a1b2c3d4-...",
  "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
  "verified_at": "2026-06-07T10:00:00Z",
  "result": "VALID",
  "signature_verified": false,
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
  "mismatch_details": []
}
```

**Enforce HITL and attestation via query params:**

```bash
curl "http://localhost:8000/agent/verify?manifest_id=<id>&enforce_hitl=true&enforce_attestation=true"
```

---

## Configuring minimum attestation level

`VerificationContext.enforce_attestation=True` requires that `attestation_verified` is `True` in the result. Manifests without hardware attestation return `ATTESTATION_UNAVAILABLE`.

In production, reject any result where `attestation_verified` is `False`:

```python
ctx = VerificationContext(enforce_attestation=True)
result = verify_manifest(manifest_dict, ctx, revocation_store)

if not result.attestation_verified:
    raise PermissionError(
        "Production requires hardware attestation (Level 2+). "
        "Use SEVSNPProvider, TDXProvider, or OPAQUEProvider."
    )
```

---

## Reading `VerificationResult` and acting on each outcome

| `result` value | Meaning | Recommended action |
|---------------|---------|-------------------|
| `VALID` | All checks passed | Allow the request |
| `REVOKED` | Manifest is in the revocation list | Block immediately; open an incident |
| `EXPIRED` | `expires_at` is in the past | Block; agent must re-issue the manifest |
| `MISMATCH` | One or more artifact hashes differ | Block; agent may have drifted or been tampered with |
| `ATTESTATION_UNAVAILABLE` | `enforce_attestation` set but no attestation present | Block in prod, warn in dev |
| `INCOMPLETE` | `strict_artifact_verification` set and bound fields lack runtime hashes | Block |
| `INCOMPATIBLE_VERSION` | Manifest spec version not supported | Upgrade the SDK |

Inspect `mismatch_details` to identify which artifacts failed:

```python
if result.result == OverallResult.MISMATCH:
    for detail in result.mismatch_details:
        print(f"  [{detail.field}] expected={detail.expected_hash} got={detail.actual_hash}")
```

---

## FastAPI middleware that gates requests on manifest ID

Use the `X-Agent-Manifest-ID` header to identify the calling agent. The middleware verifies the manifest before routing to your handler.

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

app = FastAPI()
manifest_store: dict = {}
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
                content={
                    "detail": result.result,
                    "mismatch_details": [d.model_dump() for d in result.mismatch_details],
                },
            )
    return await call_next(request)

@app.post("/execute")
async def execute(request: Request):
    return {"status": "ok"}
```

---

## Configuring CRL checking

Wire `FileCRL` into the `RevocationStore` at startup so every `verify_manifest()` call checks revocation.

```python
from pathlib import Path
from agent_manifest._revocation import FileCRL
from agent_manifest._verify import RevocationRecord, RevocationStore

crl = FileCRL(Path("/data/revocations.jsonl"))
revocation_store = RevocationStore()

for rec in crl.all_records():
    revocation_store.revoke(RevocationRecord(
        manifest_id=rec.manifest_id,
        revoked_at=rec.revoked_at,
        reason=rec.reason,
        revoked_by=rec.revoked_by,
    ))
```

`RevocationStore` is in-memory. For a long-running service, reload the CRL periodically or replace it with a database-backed store.

---

## What's next

- [Tutorial: A2A delegation chains](delegation-chains.md)  -  verify multi-hop delegation manifests
- [Tutorial: Revocation and key rotation](revocation-and-key-rotation.md)  -  revoke a manifest and update the CRL
- [Tutorial: Deploying the verification endpoint](deploying-the-verification-endpoint.md)  -  containerise and run in production
