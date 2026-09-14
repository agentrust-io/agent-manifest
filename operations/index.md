# Operations

Operate the issuer, evidence distribution, and recipient verification checks. Start with the [local verification service](https://manifest.agentrust-io.com/tutorials/deploying-the-verification-endpoint/index.md), then define how your deployment distributes trust, refreshes evidence, and handles rejected records.

| Guide                                                                                   | What it covers                                                                 |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| [Key rotation](https://manifest.agentrust-io.com/operations/key-rotation/index.md)      | Distributing new trust, issuing replacement IDs, and handling compromised keys |
| [Audit log management](https://manifest.agentrust-io.com/operations/audit-log/index.md) | Storage, retention, querying, and Rekor transparency log integration           |
| [Monitoring](https://manifest.agentrust-io.com/operations/monitoring/index.md)          | Tested verdict/error metrics, latency queries, and alert interpretation        |

## Operational model

Assign ownership for these responsibilities; the SDK does not require three separately deployed services:

1. **Issuance and key custody.** Approve the configuration, sign the manifest, protect issuer keys, and distribute trusted public keys independently. Choose key custody according to the required assurance and deployment architecture.
1. **Revocation and evidence distribution.** Publish authenticated updates and define refresh, maximum accepted age, and failure policy for each recipient. `RevocationStore` does not fetch updates, and `FileCRL` does not continuously poll another process's file writes.
1. **Recipient verification and authorization.** Supply approved keys and independent runtime observations, appraise required evidence, and reject unacceptable results before side effects. Verification can run in application code or a service; a sidecar is one deployment option. Caller authentication and operation authorization remain application responsibilities.

Monitor failures and stale evidence without treating every rejected manifest as a service outage. Test rotation and refresh behavior across every worker before relying on an availability or propagation target.
