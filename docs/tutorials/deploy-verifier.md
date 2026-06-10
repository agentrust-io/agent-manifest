# Deploying the verification endpoint

The agent-manifest SDK ships a FastAPI router that you can deploy as a standalone verification service, a sidecar, or embedded in an existing API. After this tutorial you will be able to:

- Package the verifier as a Docker container
- Configure the manifest store and CRL
- Expose the `.well-known` discovery endpoint
- Add health checks and readiness probes
- Run the complete stack with docker-compose

## Prerequisites

```bash
pip install "agent-manifest[server]"
```

---

## Architecture choices

| Deployment mode | When to use |
|-----------------|-------------|
| **Sidecar** | Each agent service runs its own verifier alongside it  -  simplest, no network hop |
| **Centralized service** | Shared verifier for a fleet  -  single manifest store, easier CRL management |
| **Embedded** | Verifier mounted directly in the main application's FastAPI app  -  fewest moving parts |

This tutorial uses the **embedded** pattern (fewest dependencies) but the Docker and config sections apply to all modes.

---

## Step 1: The application

```python
# app.py
import json
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from agent_manifest._verify import RevocationStore, create_router
from agent_manifest._revocation import FileCRL, create_crl_router

# ── Config ─────────────────────────────────────────────────────────────────
MANIFEST_DIR = Path("/data/manifests")
CRL_PATH     = Path("/data/crl.jsonl")

# ── Startup ────────────────────────────────────────────────────────────────
manifest_store: dict[str, dict] = {}
revocation_store = RevocationStore()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load all manifests from disk at startup
    for path in MANIFEST_DIR.glob("*.json"):
        m = json.loads(path.read_text())
        manifest_store[m["manifest_id"]] = m

    # Load the CRL into the revocation store
    crl = FileCRL(CRL_PATH)
    for rec in crl.all_records():
        from agent_manifest._verify import RevocationRecord
        revocation_store.revoke(RevocationRecord(
            manifest_id=rec.manifest_id,
            revoked_at=rec.revoked_at,
            reason=rec.reason,
            revoked_by=rec.revoked_by,
        ))

    yield

app = FastAPI(title="Agent Manifest Verifier", lifespan=lifespan)

# ── Routes ─────────────────────────────────────────────────────────────────

# Verification endpoints: GET /agent/verify, GET /agent/revocation-status
app.include_router(create_router(manifest_store, revocation_store), prefix="/agent")

# CRL discovery endpoints: GET /.well-known/agent-manifest/revocation[/{id}]
crl_live = FileCRL(CRL_PATH)
app.include_router(create_crl_router(crl_live))

# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/healthz")
def healthz():
    return {"status": "ok", "manifests": len(manifest_store)}

@app.get("/readyz")
def readyz():
    if not manifest_store:
        return {"status": "no manifests loaded"}, 503
    return {"status": "ready"}
```

---

## Step 2: Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir "agent-manifest[server]" uvicorn[standard]

COPY app.py .

# Manifest store and CRL live in /data  -  mount as a volume
RUN mkdir /data

EXPOSE 8080

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
```

```bash
docker build -t agent-manifest-verifier .
```

---

## Step 3: docker-compose

```yaml
# docker-compose.yml
services:
  verifier:
    image: agent-manifest-verifier
    ports:
      - "8080:8080"
    volumes:
      - ./manifests:/data/manifests:ro   # manifest JSON files
      - ./crl.jsonl:/data/crl.jsonl      # CRL file (writable)
    environment:
      UVICORN_WORKERS: "2"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/healthz"]
      interval: 10s
      timeout: 5s
      retries: 3

  # Example: an agent service that verifies itself at startup
  kyc-agent:
    image: your-kyc-agent:latest
    environment:
      VERIFIER_URL: "http://verifier:8080"
      MANIFEST_ID:  "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"
    depends_on:
      verifier:
        condition: service_healthy
```

```bash
docker-compose up

# Verify the kyc-agent manifest
curl "http://localhost:8080/agent/verify?manifest_id=018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"

# Browse the CRL
curl "http://localhost:8080/.well-known/agent-manifest/revocation"
```

---

## Step 4: Environment variable configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MANIFEST_DIR` | `/data/manifests` | Directory containing manifest JSON files |
| `CRL_PATH` | `/data/crl.jsonl` | Path to the CRL JSON-Lines file |
| `UVICORN_WORKERS` | `1` | Number of uvicorn worker processes |
| `UVICORN_LOG_LEVEL` | `info` | Logging level |

Update `app.py` to read these from the environment:

```python
import os

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/data/manifests"))
CRL_PATH     = Path(os.getenv("CRL_PATH", "/data/crl.jsonl"))
```

---

## Step 5: Kubernetes deployment

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
            - name: MANIFEST_DIR
              value: /data/manifests
            - name: CRL_PATH
              value: /data/crl.jsonl
          volumeMounts:
            - name: manifests
              mountPath: /data/manifests
              readOnly: true
            - name: crl
              mountPath: /data
          livenessProbe:
            httpGet:
              path: /healthz
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
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

## Step 6: Hot-reloading manifests

The startup `lifespan` loads manifests once. In production you will add new agents without restarting. Two approaches:

**Option A: Reload endpoint** (simplest)

```python
@app.post("/admin/reload", include_in_schema=False)
async def reload_manifests():
    manifest_store.clear()
    for path in MANIFEST_DIR.glob("*.json"):
        m = json.loads(path.read_text())
        manifest_store[m["manifest_id"]] = m
    return {"loaded": len(manifest_store)}
```

Protect this endpoint with network policy or an API key.

**Option B: Shared database** (recommended for fleets)

Replace `manifest_store: dict` with a database-backed store. On each request the verifier reads from the database  -  no reload needed, and multiple replicas stay consistent.

---

## What's next

- [Tutorial: Revocation and key rotation](revocation.md)  -  update the CRL in the running verifier
- [Operations: Monitoring the verification endpoint](../operations/monitoring.md)  -  metrics and alerting
- [Operations: Key rotation runbook](../operations/key-rotation.md)
