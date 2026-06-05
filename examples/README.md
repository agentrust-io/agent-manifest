# Examples

Complete manifest JSON for each conformance level and feature. Hash values in `level0-software-only.json` and `level1-tpm-attested.json` are illustrative placeholders. Hashes in the `multi-artifact/` example are computed from the actual artifact files in that directory.

| File / Directory | Level | Description |
|-----------------|-------|-------------|
| `level0-software-only.json` | Level 0 | Software-signed manifest for a document summarization agent. No TEE required. Suitable for development and staging. |
| `level1-tpm-attested.json` | Level 1 | TPM-attested manifest for a payment authorization agent. Includes hardware attestation block and transparency log entry. |
| `delegation-chain/` | Level 0 | Two-hop A2A delegation chain: orchestrator → executor → data-fetcher. Demonstrates scope narrowing and tamper detection. |
| `revocation/` | Level 0 | Revocation lifecycle: manifest valid → CRL populated → manifest rejected. Includes a runnable demo script. |
| `hitl/` | Level 0 | HITL-approved manifest with a populated `hitl_record`. Demonstrates `enforce_hitl` verification and approval expiry. |
| `multi-artifact/` | Level 0 | Manifest with four artifact bindings: model, prompt, tool catalog, RAG corpus. Real SHA-256 hashes from included artifact files. Tamper detection demo. |

## Running the demo scripts

From the repo root:

```bash
bash examples/delegation-chain/verify.sh
bash examples/revocation/demo.sh
bash examples/hitl/verify.sh
bash examples/multi-artifact/verify.sh
```

All scripts require Python 3.11+ and the `agent-manifest` package:

```bash
pip install -e "python/"
```

## Further reading

- [Getting started](../docs/getting-started.md) — step-by-step walkthrough of creating and verifying manifests with the Python SDK and CLI
- [Tutorials](../docs/tutorials/) — detailed guides for delegation chains, revocation, HITL, hardware attestation, and server-side verification
- [Spec](../spec/agent-manifest-spec-v0.1.md) — full data model and field cardinality rules
