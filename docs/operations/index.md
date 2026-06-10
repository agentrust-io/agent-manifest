# Operations

Production runbooks and operational guides for teams running agent-manifest in production.

| Guide | What it covers |
|-------|---------------|
| [Key rotation](key-rotation.md) | Rotating a signing key with zero downtime, rollback procedure |
| [Audit log management](audit-log.md) | Storage, retention, querying, and Rekor transparency log integration |
| [Monitoring](monitoring.md) | Metrics, alert conditions, and example Grafana dashboard |

## Operational model

Agent-manifest has three operational components you need to run:

1. **Signing authority**  -  the issuer that holds the private key and signs manifests. This is typically a CI/CD job or a secrets-manager-backed service. The signing key must never be stored in the agent process.

2. **CRL endpoint**  -  serves the certificate revocation list at `.well-known/agent-manifest/revocation`. This must be highly available  -  verifiers poll it continuously.

3. **Verification sidecar**  -  the FastAPI router (`create_router()`) that runs alongside each agent. See [Tutorial: Deploying the verifier](../tutorials/deploy-verifier.md) for the deployment pattern.

Each guide covers the operational concerns specific to one of these components.
