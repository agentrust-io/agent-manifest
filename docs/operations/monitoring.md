# Monitor verification outcomes

Measure completed verdicts, unexpected errors, and verification latency separately. A healthy verifier can reject an invalid manifest; increasing the proportion of `VALID` results is not a reliability objective.

## Run a metrics example

Complete the [first-manifest example](../getting-started.md), install `prometheus-client` with `python -m pip install prometheus-client`, then append this block to `first_manifest.py` and run it again. It records one accepted result, one mismatch, and one deliberate exception.

```python
import time
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest

def make_verifier_metrics(operation=verify_manifest):
    registry = CollectorRegistry()
    outcomes = Counter(
        "agent_manifest_verifications_total", "Verification attempts by outcome",
        ["result"], registry=registry,
    )
    latency = Histogram(
        "agent_manifest_verification_duration_seconds", "Time inside the verifier",
        buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0],
        registry=registry,
    )
    def measured_verify(received, approved_context, revocations):
        started = time.perf_counter()
        outcome = "ERROR"
        try:
            result = operation(received, approved_context, revocations)
            outcome = result.result.value
            return result
        finally:
            outcomes.labels(result=outcome).inc()
            latency.observe(time.perf_counter() - started)
    return registry, measured_verify

registry, measured_verify = make_verifier_metrics()
assert measured_verify(record, context, RevocationStore()).result.value == "VALID"
assert measured_verify(record, drift, RevocationStore()).result.value == "MISMATCH"
assert registry.get_sample_value("agent_manifest_verifications_total", {"result": "VALID"}) == 1
assert registry.get_sample_value("agent_manifest_verifications_total", {"result": "MISMATCH"}) == 1
assert registry.get_sample_value("agent_manifest_verification_duration_seconds_count") == 2
print("PASS: accepted and rejected verdicts are counted separately")

def unavailable_verifier(*args):
    raise RuntimeError("synthetic verifier failure")

error_registry, failing_verify = make_verifier_metrics(unavailable_verifier)
try:
    failing_verify(record, context, RevocationStore())
except RuntimeError:
    pass
else:
    raise AssertionError("Metrics wrapper swallowed the exception")
assert error_registry.get_sample_value("agent_manifest_verifications_total", {"result": "ERROR"}) == 1
assert error_registry.get_sample_value("agent_manifest_verification_duration_seconds_count") == 1
print("PASS: unexpected error counted and propagated")
print(generate_latest(registry).decode("utf-8"))
```

The histogram covers the wrapped verifier call, including exceptions. It excludes HTTP transport, queueing, and any evidence fetching performed before the call. `ERROR` is this wrapper's exception label, not an SDK verdict. The counter resets when its process restarts.

## Connect it to the service

Move `make_verifier_metrics` and its imports into your service module. Inside the [deployment guide's `create_app()`](../tutorials/deploying-the-verification-endpoint.md#create-verifierpy), create `registry, measured_verify = make_verifier_metrics()` once. In the `/verify` handler, replace the `verify_manifest(...)` call with `measured_verify(...)`.

Expose a `/metrics` route returning `Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)`, importing `Response` from FastAPI and `CONTENT_TYPE_LATEST` from `prometheus_client`. Keep the registry shared by that app's requests; creating one per request loses the history. Unknown IDs rejected before the verifier call need a separate HTTP request counter if you want to measure them.

This registry is for one worker. Multiple worker processes need the client's [multiprocess configuration](https://prometheus.github.io/client_python/multiprocess/) or a separate scrape target per process. Protect the metrics endpoint according to your deployment policy. Keep manifest IDs, agent IDs, hashes, URLs, and raw error messages out of metric labels.

See the [Python counter documentation](https://prometheus.github.io/client_python/instrumenting/counter/) for reset and label behavior. The SDK does not automatically install this instrumentation.

## Query what was measured

Configure Prometheus to scrape the service under a job named `manifest-verifier`, or replace that job selector in these queries.

| Signal | PromQL | Interpretation |
|--------|--------|----------------|
| Outcomes per second | `sum by (result) (rate(agent_manifest_verifications_total{job="manifest-verifier"}[5m]))` | Verification attempts grouped by their result. |
| Unexpected errors | `sum(rate(agent_manifest_verifications_total{job="manifest-verifier",result="ERROR"}[5m]))` | Exceptions in the wrapped operation; inspect application logs. |
| Fleet p99 verifier latency | `histogram_quantile(0.99, sum by (le) (rate(agent_manifest_verification_duration_seconds_bucket{job="manifest-verifier"}[5m])))` | Estimated latency for the measured operation across workers. |
| Failed scrape | `up{job="manifest-verifier"} == 0` | Prometheus could not scrape a configured target; investigate service, network, and scrape configuration. |

Use separate queries for p50, p95, and p99. `0.50|0.95|0.99` is not a valid quantile argument. The [Prometheus function reference](https://prometheus.io/docs/prometheus/latest/querying/functions/) describes histogram aggregation and missing-series behavior.

`absent(agent_manifest_verifications_total)` only establishes that the selected series is absent. It does not prove the service is down: a labeled counter may not exist before the first call. A removed scrape target also needs monitoring of service discovery or expected target inventory; `up == 0` alone cannot detect every missing target.

## Choose alerts from service policy

Select thresholds and evaluation windows from measured traffic and the service's objectives. This guide supplies no measured latency, uptime, or revocation-propagation guarantee.

- A `MISMATCH` spike means more failed comparisons or signatures. Examine details before concluding tampering or replay.
- A `REVOKED` spike counts verification attempts against revoked IDs. Repeated requests for one ID can cause it; it does not count new revocations.
- `INCOMPLETE` commonly means a declared artifact lacks the required independent runtime observation. Inspect the actual result fields rather than assuming missing human approval.
- Higher latency does not identify a slow CRL or transparency service. Instrument those operations separately if the application calls them; the demo uses an in-memory revocation store.
- Track revocation freshness and propagation at the distribution/refresh boundary. Neither of the two metrics above measures them.

Separate availability and processing-error objectives from authorization outcomes. Rejecting a bad record is expected behavior, and a high acceptance rate can hide a verifier that accepts too much.

## Other telemetry backends

With OpenTelemetry, instrument the same call boundary and preserve verdict/exception distinctions. Configure a metric reader and exporter in the hosting application; creating a meter and instruments alone does not deliver metrics to a backend. Use your deployment's existing telemetry configuration and test delivery with an intentional request and failure before relying on alerts.
