# Run a verification service

Load a signed manifest, verify it against server-held inputs, and expose the verdict over HTTP. This walkthrough starts locally, then packages the same service in a container. It loads signed revocations into the store used by verification.

## Prepare the demo inputs

Complete the [first-manifest tutorial](../getting-started.md). Append this block to `first_manifest.py` and run it once. It saves the demo's independently configured context and public revocation key; no private key is written. Use a new `data` directory for this exercise.

```python
from agent_manifest._revocation import sign_revocation

data = Path("data")
data.mkdir(exist_ok=False)
(data / "manifest.json").write_text(json.dumps(record), encoding="utf-8")
(data / "context.json").write_text(context.model_dump_json(), encoding="utf-8")
revoker = generate_ed25519()
(data / "revoker.hex").write_text(revoker.public_bytes.hex(), encoding="utf-8")
# A signed revocation for another demo ID proves the loader handles real entries.
entry = sign_revocation(
    manifest_id="019236ab-cdef-7000-8000-000000000099",
    reason="demo withdrawal", revoked_by="spiffe://example.test/security", keypair=revoker,
)
(data / "revocations.jsonl").write_text(entry.model_dump_json() + "\n", encoding="utf-8")
print("Saved demo service inputs in data/")
```

For a real service, provision `context.json` and `revoker.hex` through the recipient's own trust configuration. Never derive trusted keys or expected runtime hashes from an incoming manifest. This demo context covers one known configuration, not a fleet of arbitrary agents.

## Create `verifier.py`

Save this complete block beside `data/`. The app factory reads all inputs before returning a ready application. Missing files, malformed revocation entries, and bad revocation signatures fail startup.

```python
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from agent_manifest import VerificationContext, verify_manifest
from agent_manifest._revocation import SignedRevocationRecord, verify_revocation_signature
from agent_manifest._verify import RevocationRecord, RevocationStore


def create_app():
    data = Path(os.environ.get("MANIFEST_DATA_DIR", "data"))
    manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
    context = VerificationContext.model_validate_json(
        (data / "context.json").read_text(encoding="utf-8")
    )
    if not context.trusted_keys:
        raise ValueError("Configure trusted issuer keys before starting")
    revoker = bytes.fromhex((data / "revoker.hex").read_text(encoding="utf-8").strip())
    if len(revoker) != 32:
        raise ValueError("Expected a raw Ed25519 public key")
    revocations = RevocationStore()
    for line in (data / "revocations.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = SignedRevocationRecord.model_validate_json(line)
        verify_revocation_signature(entry, revoker)
        revocations.revoke(RevocationRecord(
            manifest_id=entry.manifest_id, revoked_at=entry.revoked_at,
            reason=entry.reason, revoked_by=entry.revoked_by,
        ))

    app = FastAPI(title="Local manifest verifier")

    @app.get("/verify")
    async def verify(manifest_id: str):
        if manifest_id != manifest["manifest_id"]:
            raise HTTPException(status_code=404, detail="Unknown manifest")
        return verify_manifest(manifest, context, revocations).model_dump(mode="json")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/ready")
    async def ready():
        return {"status": "loaded"}

    return app
```

This small service exposes only `/verify`, `/health`, and `/ready`. Readiness means the configured inputs loaded; it does not mean the manifest is acceptable. An expired or revoked manifest can produce a rejection verdict from a healthy service.

## Run and query it

From the source checkout used in the first tutorial:

```bash
python -m pip install -e "./python[server]"
python -m uvicorn verifier:create_app --factory --host 127.0.0.1 --port 8080
```

In another terminal:

```bash
curl "http://127.0.0.1:8080/verify?manifest_id=019236ab-cdef-7000-8000-000000000001"
curl http://127.0.0.1:8080/ready
```

The fresh demo returns a JSON verdict with `result: "VALID"` and `signature_verified: true`. An unknown ID returns HTTP 404. A processed verification can return HTTP 200 with a rejected verdict: the caller must inspect `result` and reject every non-`VALID` outcome.

## Package the same service

Save this as `Dockerfile` at the checkout root. Building from the same `python/` source keeps the service aligned with the code used locally.

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY python/ /sdk/
RUN pip install --no-cache-dir "/sdk[server]"
COPY verifier.py /app/verifier.py
CMD ["python", "-m", "uvicorn", "verifier:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080"]
```

Save `compose.yaml` alongside it:

```yaml
services:
  verifier:
    build: .
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - ./data:/data:ro
    environment:
      MANIFEST_DATA_DIR: /data
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/ready', timeout=2).close()"]
      interval: 10s
      timeout: 5s
      retries: 3
```

Stop the local server before starting the container on the same port:

```bash
docker compose up --build
```

The health check uses Python from the image. The service is published on localhost and reads its mounted inputs without writing them.

## Refresh and operate it

This example snapshots files at startup. File changes do not update the running worker. Validate and publish an entire new configuration snapshot, then restart every worker; `docker compose restart verifier` reloads the mounted files in this local example. There is no unauthenticated reload endpoint.

Signed entries establish who issued each revocation, not that the list is complete or current. An empty, truncated, or stale file needs separate detection through your authenticated distribution and freshness policy. The explicit loader above raises on invalid entries instead of using `FileCRL`'s skip-invalid-entry behavior. See [revocation and key rotation](revocation-and-key-rotation.md).

Before exposing a service beyond localhost, add authenticated callers, operation authorization, request limits, transport protection, and evidence-refresh policy. A manifest ID identifies a document, not the requesting agent. A central service requires a network request; an embedded verifier avoids that request, while a sidecar usually uses local IPC or loopback. Choose based on trust ownership and deployment requirements rather than an assumed latency ranking.

For a protected operation in the application itself, follow [server-side verification](server-side-verification.md). The container configuration here does not provision a production cluster or hardware attestation.
