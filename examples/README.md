# Examples

Complete manifest JSON for each conformance level. Hash values are illustrative placeholders — real implementations must compute actual SHA-256 hashes of the bound artifacts.

| File | Level | Description |
|------|-------|-------------|
| `level0-software-only.json` | Level 0 | Software-signed manifest for a document summarization agent. No TEE required. Suitable for development and staging. |
| `level1-tpm-attested.json` | Level 1 | TPM-attested manifest for a payment authorization agent. Includes hardware attestation block and transparency log entry. |

See [docs/getting-started.md](../docs/getting-started.md) for a step-by-step walkthrough of creating and verifying these manifests with the Python SDK and CLI.

For the full data model and field cardinality rules, see [spec/agent-manifest-spec-v0.1.md](../spec/agent-manifest-spec-v0.1.md), Section 3.
