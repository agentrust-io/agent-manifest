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
| **Sidecar** | Each agent service runs its own verifier alongside it - no network hop, lowest latency |
| **Centralized service** | Shared verifier for a fleet - single manifest store, easier CRL management |
| **Embedded in API gateway** | Verifier mounted directly in the main application - fewest moving parts |

This tutorial packages the verifier as a standalone container, which works for all three modes.

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

This mounts the following endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/agent/verify?manifest_id=...` | Returns a `VerificationResult` |
| `POST` | `/agent/verify` | Verify with caller-supplied trusted keys |
| `GET` | `/agent/revocation-status?manifest_id=...` | Returns revocation record or 404 |
| `GET` | `/.well-known/agent-manifest/revocation` | Full CRL as JSON array |
| `GET` | `/.well-known/agent-manifest/revocation/{id}` | Single CRL entry or 404 |
| `GET` | `/.well-known/agent-manifest` | RFC 8615 discovery document |
| `GET` | `/health` | Liveness probe |
| `GET` | `/ready` | Readiness probe |

`RevocationStore` in this example is in-memory. For production, replace it with a database-backed store that is shared across replicas and persists across restarts.

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
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  agent-service:
    image: python:3.12-slim
    command: ["echo", "Replace with your agent service"]
    depends_on:
      verifier:
        condition: service_healthy
```

```bash
# Create the data directory and a blank CRL file
mkdir -p data && touch data/revocations.jsonl

docker-compose -f examples/docker-compose-verifier.yml up

# Verify a manifest
curl "http://localhost:8080/agent/verify?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

# Browse the CRL
curl "http://localhost:8080/.well-known/agent-manifest/revocation"

# Use the discovery document
curl http://localhost:8080/.well-known/agent-manifest
# {"revocation":"/.well-known/agent-manifest/revocation","verify":"/agent/verify"}
```

---

## Kubernetes deployment

```yaml
# k8s/verifier-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-manifest-verifier
spec:
  replicas: 2
  selector:
    matchLabels:
      app: agent-manifest-verifier
  template:
    metadata:
      labels:
        app: agent-manifest-verifier
    spec:
      containers:
        - name: verifier
          image: agent-manifest-verifier:latest
          ports:
            - containerPort: 8080
          env:
            - name: CRL_PATH
              value: /data/revocations.jsonl
          volumeMounts:
            - name: manifests
              mountPath: /data/manifests
              readOnly: true
            - name: crl
              mountPath: /data
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
      volumes:
        - name: manifests
          configMap:
            name: agent-manifests
        - name: crl
          persistentVolumeClaim:
            claimName: crl-pvc
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

## Hot-reloading manifests

The in-memory `manifest_store` is populated at startup. In production you will add new agents without restarting. Two approaches:

**Option A: Reload endpoint** (simplest)

```python
@app.post("/admin/reload", include_in_schema=False)
async def reload_manifests():
    manifest_store.clear()
    for path in Path("/data/manifests").glob("*.json"):
        import json
        m = json.loads(path.read_text())
        manifest_store[m["manifest_id"]] = m
    return {"loaded": len(manifest_store)}
```

Protect this endpoint with network policy or an API key.

**Option B: Shared database** (recommended for fleets)

Replace `manifest_store: dict` with a database-backed store. On each request the verifier reads from the database - no reload needed, and multiple replicas stay consistent.

---

## Summary

This tutorial built a containerised verification service that exposes the RFC 8615 discovery endpoint, a full-featured verification route, and the CRL endpoint. The same `verifier.py` works as a sidecar, a centralised service, or embedded in your API gateway. See [Revocation and key rotation](revocation-and-key-rotation.md) to update the CRL in the running verifier, and [Operations: Monitoring](../operations/monitoring.md) for metrics and alerting.
