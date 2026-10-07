# Operations

These guides are for the people who keep Agent Manifest running day to day: whoever holds the signing keys, whoever publishes revocations (records that withdraw a manifest early), and whoever runs the services that check manifests. They cover changing keys, keeping audit records, and watching for problems.

Start with the [local verification service](../tutorials/deploying-the-verification-endpoint.md), then decide how your deployment hands out trusted keys, keeps evidence current, and deals with rejected records.

| Guide | What it covers |
|-------|---------------|
| [Key rotation](key-rotation.md) | Distributing new trust, issuing replacement IDs, and handling compromised keys |
| [Audit log management](audit-log.md) | Storage, retention, querying, and Rekor transparency log integration |
| [Monitoring](monitoring.md) | Tested verdict/error metrics, latency queries, and alert interpretation |

## Operational model

Three jobs need a named owner. They can live in one service or several; the SDK does not require three separately deployed services:

1. **Issuance and key custody.** Approve the configuration, sign the manifest, protect issuer keys, and distribute trusted public keys independently. Choose key custody according to the required assurance and deployment architecture.

2. **Revocation and evidence distribution.** Publish authenticated updates and define refresh, maximum accepted age, and failure policy for each recipient. `RevocationStore` does not fetch updates, and `FileCRL` does not continuously poll another process's file writes.

3. **Recipient verification and authorization.** Supply approved keys and independent runtime observations, appraise required evidence, and reject unacceptable results before side effects. Verification can run in application code or a service; a sidecar is one deployment option. Caller authentication and operation authorization remain application responsibilities.

Watch for failures and out-of-date evidence, but do not treat every rejected manifest as an outage: rejecting a bad record is the system working. Test rotation and refresh behavior across every worker before relying on an availability or propagation target.
