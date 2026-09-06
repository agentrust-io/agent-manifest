# Server-side manifest verification

Reject a protected request when its manifest is missing, unknown, or fails verification. This local FastAPI example uses the signed record and independently configured inputs from the [first-manifest tutorial](../getting-started.md). It tests the gate without starting a network server.

## Run the request gate

Complete the first-manifest tutorial, install the server dependencies with `python -m pip install -e "./python[server]"`, then append this block to `first_manifest.py` and run `python first_manifest.py` again.

The demo's manifest header selects a stored document. It does not authenticate a caller. Before using this in a service, bind the authenticated caller to an allowed manifest and separately authorize the operation. Anyone who knows the demo ID can select its record.

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from agent_manifest import OverallResult
from agent_manifest._verify import create_router

app = FastAPI()
manifest_store = {record["manifest_id"]: record}
approved_context = context
revocations = RevocationStore()

@app.middleware("http")
async def check_manifest(request: Request, call_next):
    if request.url.path == "/execute":
        manifest_id = request.headers.get("x-agent-manifest-id")
        received = manifest_store.get(manifest_id)
        if received is None:
            return JSONResponse(status_code=403, content={"detail": "Manifest required or unknown"})
        result = verify_manifest(received, approved_context, revocations)
        if result.result != OverallResult.VALID:
            return JSONResponse(status_code=403, content={"detail": result.result.value})
    return await call_next(request)

@app.post("/execute")
async def execute():
    return {"status": "accepted demo request"}

# Diagnostic routes are separate from the protected operation above.
app.include_router(create_router(manifest_store, revocations), prefix="/agent")

with TestClient(app) as client:
    headers = {"x-agent-manifest-id": record["manifest_id"]}
    assert client.post("/execute", headers=headers).status_code == 200
    assert client.post("/execute").status_code == 403
    assert client.post("/execute", headers={"x-agent-manifest-id": "unknown"}).status_code == 403
    print("PASS: known manifest accepted; missing and unknown IDs rejected")

    approved_context = context.model_copy(update={"system_prompt_hash": "sha256:" + "0" * 64})
    rejected = client.post("/execute", headers=headers)
    assert rejected.status_code == 403 and rejected.json()["detail"] == "MISMATCH"
    print("PASS: changed runtime input rejected before the handler")

    diagnostic = client.get("/agent/verify", params={"manifest_id": record["manifest_id"]})
    assert diagnostic.status_code == 200
    assert diagnostic.json()["result"] == "UNVERIFIABLE"
    assert diagnostic.json()["signature_verified"] is False
    print("PASS: diagnostic GET without trusted keys cannot return VALID")
```

The gate requires `VALID` using server-held keys and runtime observations. Keep the route policy explicit when adding protected operations; this demo protects only `/execute`. Production services also need caller authentication, authorization, bounded requests, and current revocation and attestation appraisal.

## What the SDK router provides

| Route | Trust and result boundaries |
|-------|-----------------------------|
| `GET /agent/verify?manifest_id=...` | Looks up a stored JSON manifest but receives no trusted issuer keys. The signed demo returns `UNVERIFIABLE`; this is not an acceptance gate. |
| `POST /agent/verify` | Accepts trust and evidence claims from the request body. A service must not treat an untrusted caller's chosen keys or claims as its own authorization policy. Bound artifacts can still lack runtime comparisons. |
| `POST /agent/verify/cose` | Accepts a v0.2 COSE envelope with `Content-Type: application/agent-manifest+cose`. Configure the router's `cose_context` with server-held trust and runtime inputs. No configured trust means no `VALID` result. |
| `GET /agent/revocation-status?manifest_id=...` | Looks up the in-memory revocation store. It does not fetch or refresh a CRL. |

An HTTP 200 response means the verification request was processed. Inspect the result body; a non-`VALID` verdict must not authorize the protected operation. The SDK router does not provide caller authentication, rate limiting, or application authorization.

## Configure the verifier's inputs

Use `VerificationContext` to supply independently observed hashes, model version, enforcement mode, trusted issuer keys, and any required delegation or approval keys. With strict artifact verification, a declared binding without its required observation can yield `INCOMPLETE`. Do not fill expected values by copying the incoming manifest.

`trusted_keys` authenticates the signature under a configured key. Where issuer identity matters, also populate `trusted_key_issuers` to restrict which issuer each key may represent. An empty issuer map does not authorize that named issuer merely because the signature verifies.

Keep `strict_artifact_verification=True` for the application gate. Setting it to `False` deliberately reduces artifact checking; label such an audit as document verification and do not use it to approve the running agent.

## Read the verdict

| Result | Meaning for the gate |
|--------|----------------------|
| `VALID` | Supplied checks passed for the declared bindings; separately check caller identity and permission for the operation. |
| `SIGNATURE_MISSING` or `UNVERIFIABLE` | Required signature or usable trust is missing; reject. |
| `REVOKED` | The configured revocation store rejects the ID. |
| `EXPIRED` | The validity check failed. |
| `MISMATCH` | Inspect `mismatch_details` and `signature_verified`; a signature, artifact, delegation, or approval check can fail. |
| `INCOMPLETE` | Required artifact observations are missing. |
| `ATTESTATION_UNAVAILABLE` | Required attestation appraisal is unavailable. |
| `INCOMPATIBLE_VERSION` | The verifier cannot process this specification version. |

Reject every non-`VALID` outcome, including future values absent from this table. A true `attestation_verified` field alone cannot override another failed check.

## Add revocation and evidence appraisal

The example uses an empty `RevocationStore`. For a running service, load authenticated revocation records and refresh the store before stale data exceeds your acceptance policy. A `FileCRL` reader caches loaded records; reusing it does not automatically notice another process's writes. Follow the tested [revocation example](revocation-and-key-rotation.md).

When attestation is required, appraise the hardware evidence and its binding to this manifest using approved roots and freshness policy before supplying verified evidence to the context. `enforce_attestation=True` does not itself perform every vendor appraisal step or establish a conformance level.

Similarly, independently appraise a transparency entry or receipt before supplying `verified_transparency_entry_ids` or `verified_transparency_receipt_hashes`, together with `transparency_evidence_manifest_id`. A receipt's presence is insufficient, including a receipt in a COSE unprotected header.

## Next steps

- [Delegation chains](delegation-chains.md): verify signed hops and scope narrowing.
- [Human approval workflows](hitl-approval-workflows.md): require an independently trusted approval signature.
- [Verification API](../api-reference/index.md): context fields and result types.
