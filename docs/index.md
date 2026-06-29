# Agent Manifest

**Cryptographically anchor all 10 artifacts defining an AI agent at deployment.**

A signed JWT proves who called an API. An Agent Manifest proves who the agent **was**, what it was **allowed to do**, how it was **built**, what it **decided**, who **approved** it, and whether any of that changed between approval and execution.

```bash
pip install "agent-manifest[cli]"
```

```bash
manifest keygen -d ./keys/
manifest create config.json -o draft.json
manifest sign draft.json --key keys/private.hex -o signed.json
manifest verify signed.json   # VALID
```

## The agent attestation gap

Every entity in a modern enterprise has a verifiable identity. Users have X.509 certificates. Services have SPIFFE SVIDs. Containers have image digests. AI agents have none of these.

An agent calling a tool today presents no unforgeable proof of which system prompt defined its behavior, which model is running, which policy was approved, or whether a human reviewed any of it. This is not an authentication gap  -  agents can authenticate with tokens. It is an **attestation gap**: the inability to prove, to a third party who does not trust the operator, that the agent running right now is the agent that was approved.

Software-signed manifests do not close this gap. A privileged operator can replace a system prompt in memory after signing, swap a model version between approval and runtime, or forge a human-in-the-loop approval record. Hardware-attested manifests make these attacks impossible  -  the measurement happens in silicon before any user code runs and the signing key never leaves the TEE.

## How it works

```
Developer                 TEE                    Verifier
─────────                 ───                    ────────
Hash 10 artifacts   →   Measure in hardware  →  Verify against
Sign manifest       →   Seal signing key     →  attestation report
Publish to log      →   Return TRACE claim   →  VALID / MISMATCH
```

A verifying party who holds an Agent Manifest and its accompanying attestation report can prove  -  without trusting the operator  -  that a specific agent ran specific code under specific policy with specific tools, produced specific decisions, and received specific human oversight.

## The 10 attested artifacts

| # | Artifact | What it proves |
|---|----------|----------------|
| 1 | System Prompt | The exact prompt defining the agent's persona and safety constraints |
| 2 | Policy Bundle | The Cedar/Rego/YAML governance rules in force |
| 3 | Tool Manifest | Every tool schema and description the agent was authorized to call |
| 4 | Model Identity | Which model and version ran (binary hash for local, version for API) |
| 5 | RAG Corpus | The knowledge base the agent was grounded on (Merkle root) |
| 6 | Memory Baseline | Approved agent memory state with TTL-based re-approval |
| 7 | Decision Trace | Hardware-signed audit chain root for all agent decisions |
| 8 | A2A Delegation | Signed delegation chain from human principal to current agent |
| 9 | Supply Chain | Container digest, SLSA provenance, SBOM, MCP server supply chain |
| 10 | HITL Approvals | Hardware-signed human oversight records (EU AI Act Art. 14) |

## Hardware providers

| Provider | Platform | Assurance |
|----------|----------|-----------|
| TPM 2.0 | Any Azure/AWS/GCP VM with Trusted Launch | Medium |
| AMD SEV-SNP | Azure DCasv5, AWS C6a Nitro, GCP N2D | High |
| Intel TDX | Azure DCedsv5, GCP C3 | High |
| OPAQUE | OPAQUE Managed Runtime | Highest |

Provider auto-selects based on available hardware: `OPAQUE → SEV-SNP → TDX → TPM → software`.

## Conformance levels

| Level | Requirements | Use case |
|-------|-------------|---------|
| Level 0 | Software signing, all artifact bindings | Development, staging |
| Level 1 | + TEE attestation, `audit_key_sealed: true` | Enterprise production, EU AI Act Art. 15 |
| Level 2 | + All 10 artifacts, HITL approvals, Phase 2 cMCP | Regulated industries, DORA |
| Level 3 | + ML-DSA-65, ML-KEM-768, SHAKE-256 | Sovereign, classified, long-horizon financial |

## Next steps

- [Getting started](getting-started.md)  -  Level 0 in 15 minutes
- [Examples](https://github.com/agentrust-io/examples)  -  complete manifest JSON for Level 0 and Level 1
- [Specification](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.1.md)  -  197 conformance tests across 5 modules
- [Architecture decisions](adr/index.md)  -  rationale behind cryptographic design choices
