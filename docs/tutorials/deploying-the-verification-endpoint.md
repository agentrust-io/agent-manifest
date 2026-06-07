# Deploying the Verification Endpoint

The agent-manifest SDK ships a FastAPI router that you can deploy as a standalone verification service, a sidecar, or embedded in an existing API. After this tutorial you will be able to:

- Package the verifier as a Docker container
- Configure the manifest store and CRL
- Expose the `.well-known` discovery endpoint (RFC 8615)
- Add health checks and Kubernetes readiness probes
- Run the complete stack with docker-compose

## Prerequisites

```bash
pip install "agent-manifest[server]"
```

---

## Architecture options

| Deployment mode | When to use |
|-----------------|-------------|
| **Sidecar** | Each agent service runs its own verifier alongside it — no network hop, lowest latency |
| **Centralized service** | Shared verifier for a fleet — single manifest store, easier CRL management |
| **Embedded in API gateway** | Verifier mounted directly in the main application — fewest moving parts |

This tutorial packages the verifier as a standalone container, which works for all three modes.

---

## Container packaging

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install "agent-manifest[server]"
COPY verifier.py .
CMD ["uvicorn", "verifier:app", "--host", "0.0.0.0", "--port", "8080"]
```

```bash
docker build -t agent-manifest-verifier .
```

---

## The full server (`verifier.py`)

```python
from fastapi import FastAPI
from agent_manifest._verify import create_router, RevocationStore
from agent_manifest._revocation import create_crl_router, FileCRL
import os

app = FastAPI(title="Agent Manifest Verifier")

manifest_store: dict = {}
crl = FileCRL(os.getenv("CRL_PATH", "/data/revocations.jsonl"))
revocation_store = RevocationStore()

app.include_router(create_router(manifest_store, revocation_store), prefix="/agent")
app.include_router(create_crl_router(crl))


@app.get("/.well-known/agent-manifest")
async def discovery():
    """RFC 8615 discovery document."""
    return {
        "revocation": "/.well-known/agent-manifest/revocation",
        "verify": "/agent/verify",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
```

This mounts the following endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/agent/verify?manifest_id=...` | Returns a `VerificationResult` |
| `GET` | `/agent/revocation-status?manifest_id=...` | Returns revocation record or 404 |
| `GET` | `/.well-known/agent-manifest/revocation` | Full CRL as JSON array |
| `GET` | `/.well-known/agent-manifest/revocation/{id}` | Single CRL entry or 404 |
| `GET` | `/.well-known/agent-manifest` | Discovery document |
| `GET` | `/health` | Liveness probe |

!!! note
    `RevocationStore` in this example is in-memory. For production, replace it with a database-backed store that is shared across replicas and persists across restarts.

---

## docker-compose setup

```yaml
# examples/docker-compose-verifier.yml
version: "3.9"
services:
  verifier:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
    environment:
      CRL_PATH: /data/revocations.jsonl

  agent-service:
    image: python:3.12-slim
    command: ["echo", "Replace with your agent service"]
```

```bash
# Create the data directory and a blank CRL file
mkdir -p data && touch data/revocations.jsonl

docker-compose -f examples/docker-compose-verifier.yml up

# Verify a manifest
curl "http://localhost:8080/agent/verify?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

# Browse the CRL
curl "http://localhost:8080/.well-known/agent-manifest/revocation"
```

---

## Environment variables reference

| Variable | Default | Description |
|----------|---------|-------------|
| `CRL_PATH` | `/data/revocations.jsonl` | Path to the JSON-Lines CRL file |
| `LOG_LEVEL` | `info` | Uvicorn log level (`debug`, `info`, `warning`, `error`) |
| `UVICORN_WORKERS` | `1` | Number of uvicorn worker processes |

Read them in `verifier.py`:

```python
import os
from pathlib import Path

CRL_PATH = Path(os.getenv("CRL_PATH", "/data/revocations.jsonl"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")
```

---

## Health checks and readiness

The `/health` endpoint returns `{"status": "ok"}` as soon as the process starts — use it for Kubernetes liveness probes. If you want a readiness gate that waits until manifests are loaded, add a separate `/ready` endpoint:

```python
@app.get("/ready")
async def ready():
    if not manifest_store:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=503,
            content={"status": "no manifests loaded"},
        )
    return {"status": "ready", "manifests": len(manifest_store)}
```

Kubernetes probe configuration:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 5
```

---

## `.well-known/agent-manifest` discovery

The discovery endpoint follows [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) (well-known URIs). Clients can `GET /.well-known/agent-manifest` to discover the verification and revocation URLs without hardcoding them.

```bash
curl http://localhost:8080/.well-known/agent-manifest
# {"revocation":"/.well-known/agent-manifest/revocation","verify":"/agent/verify"}
```

Agents bootstrapping in a new environment should use the discovery document rather than assuming fixed paths.

---

## What's next

- [Tutorial: Revocation and key rotation](revocation-and-key-rotation.md) — update the CRL in the running verifier
- [Operations: Monitoring](../operations/monitoring.md) — metrics and alerting for the verification endpoint
- [Operations: Key rotation runbook](../operations/key-rotation.md)
