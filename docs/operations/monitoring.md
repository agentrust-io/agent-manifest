# Monitoring the verification endpoint

This guide covers what metrics to expose from the verification endpoint, what alert conditions to configure, and how to integrate with Prometheus and OpenTelemetry.

---

## Key metrics

### Request counters

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `agent_manifest_verifications_total` | Counter | `result` (VALID/MISMATCH/EXPIRED/REVOKED/INCOMPLETE/ERROR) | Total verification requests |
| `agent_manifest_revocation_checks_total` | Counter | `result` (hit/miss/error) | CRL checks performed |
| `agent_manifest_manifests_active` | Gauge | `attestation_level` | Manifests in the store by attestation level |

### Latency histograms

| Metric | Buckets | Description |
|--------|---------|-------------|
| `agent_manifest_verification_duration_seconds` | `[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]` | End-to-end verification latency |
| `agent_manifest_revocation_check_duration_seconds` | `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5]` | CRL fetch + lookup latency |

---

## Adding Prometheus instrumentation

Install `prometheus-client` and wrap the verification router:

```python
from fastapi import FastAPI, Request, Response
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time

VERIFICATIONS = Counter(
    "agent_manifest_verifications_total",
    "Total verification requests",
    ["result"],
)
VERIFICATION_LATENCY = Histogram(
    "agent_manifest_verification_duration_seconds",
    "End-to-end verification latency",
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
)
REVOCATION_LATENCY = Histogram(
    "agent_manifest_revocation_check_duration_seconds",
    "CRL lookup latency",
    buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5],
)
ACTIVE_MANIFESTS = Gauge(
    "agent_manifest_manifests_active",
    "Active manifests by attestation level",
    ["attestation_level"],
)

app = FastAPI()

@app.middleware("http")
async def record_verification_metrics(request: Request, call_next):
    if request.url.path == "/verify":
        start = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start
        VERIFICATION_LATENCY.observe(duration)
        return response
    return await call_next(request)

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

Call `VERIFICATIONS.labels(result=result.result.value).inc()` in your verification handler after each call.

---

## OpenTelemetry integration

If your stack uses OpenTelemetry instead of direct Prometheus:

```python
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider

provider = MeterProvider()
metrics.set_meter_provider(provider)
meter = metrics.get_meter("agent-manifest")

verifications = meter.create_counter(
    "agent_manifest.verifications",
    description="Total verification requests",
)
verification_latency = meter.create_histogram(
    "agent_manifest.verification.duration",
    unit="s",
    description="End-to-end verification latency",
)

# In your handler:
verifications.add(1, {"result": result.result.value})
verification_latency.record(duration, {"result": result.result.value})
```

---

## Alert conditions

### Critical alerts (page immediately)

| Condition | PromQL | Meaning |
|-----------|--------|---------|
| INVALID spike | `rate(agent_manifest_verifications_total{result="MISMATCH"}[5m]) > 0.1` | Possible artifact tampering or replay attack |
| REVOKED spike | `rate(agent_manifest_verifications_total{result="REVOKED"}[5m]) > 0.5` | Active incident  -  multiple manifests being revoked |
| Verifier unreachable | `absent(agent_manifest_verifications_total)` | Verification sidecar is down |

### Warning alerts (page next business day)

| Condition | PromQL | Meaning |
|-----------|--------|---------|
| High p99 latency | `histogram_quantile(0.99, rate(agent_manifest_verification_duration_seconds_bucket[5m])) > 0.2` | CRL or Rekor lookup is slow |
| EXPIRED manifests accumulating | `rate(agent_manifest_verifications_total{result="EXPIRED"}[1h]) > 0.01` | Issuance pipeline not refreshing manifests |
| Level 0 agents above threshold | `agent_manifest_manifests_active{attestation_level="0"} > 5` | Unattested agents in production |

### Prometheus alert rules

```yaml
groups:
  - name: agent-manifest
    rules:
      - alert: ManifestTamperingDetected
        expr: rate(agent_manifest_verifications_total{result="MISMATCH"}[5m]) > 0.1
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: Manifest artifact mismatch rate elevated
          description: Possible artifact tampering or key compromise. Rate = {{ $value }} req/s.

      - alert: ManifestRevocationSpike
        expr: rate(agent_manifest_verifications_total{result="REVOKED"}[5m]) > 0.5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: High revocation rate detected
          description: Multiple manifests being revoked. Rate = {{ $value }} req/s. Check for active incident.

      - alert: VerificationLatencyHigh
        expr: histogram_quantile(0.99, rate(agent_manifest_verification_duration_seconds_bucket[5m])) > 0.2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: Verification p99 latency above 200ms
          description: Check CRL endpoint availability and Rekor response times.
```

---

## Grafana dashboard

Key panels for a verification endpoint dashboard:

**Row 1: Request health**
- Panel: `rate(agent_manifest_verifications_total[5m])` by result  -  stacked area chart
- Panel: `rate(agent_manifest_verifications_total{result!="VALID"}[5m])`  -  single stat with alert threshold

**Row 2: Latency**
- Panel: `histogram_quantile(0.50|0.95|0.99, rate(agent_manifest_verification_duration_seconds_bucket[5m]))`  -  line chart
- Panel: `histogram_quantile(0.99, rate(agent_manifest_revocation_check_duration_seconds_bucket[5m]))`  -  single stat

**Row 3: Fleet health**
- Panel: `agent_manifest_manifests_active` by `attestation_level`  -  bar gauge
- Panel: `rate(agent_manifest_verifications_total{result="EXPIRED"}[1h])`  -  single stat

**SLO targets**

| Metric | Target |
|--------|--------|
| Verification success rate (VALID) | ≥ 99.5% |
| p99 verification latency | < 50ms (local CRL) / < 200ms (remote CRL) |
| Revocation propagation time | < 30s |
| Uptime (verifier reachable) | 99.9% |

---

## What each non-VALID result means operationally

| Result | Frequency in healthy system | Cause | Response |
|--------|-----------------------------|-------|----------|
| MISMATCH | Rare (< 0.01%) | Artifact changed after issuance | Investigate  -  possible tamper |
| EXPIRED | Low (< 0.1%) | Manifest not refreshed before expiry | Fix issuance pipeline |
| REVOKED | Rare (near zero) | Expected after revocation event | Confirm revocation was intentional |
| INCOMPLETE | None | HITL required but missing | Fix approval workflow |
| ATTESTATION_UNAVAILABLE | Rare in production | Hardware provider unavailable | Check attestation hardware |
| ERROR | Near zero | Malformed manifest or unexpected exception | Check logs |
