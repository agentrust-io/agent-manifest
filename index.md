# Agent Manifest

Agent Manifest is an open standard for the cryptographic identity and provenance of AI agents. It anchors all 10 artifacts that define an agent at deployment, so a verifier who does not trust the operator can prove the agent running in production is the exact agent that was approved.

**Cryptographically anchor all 10 artifacts defining an AI agent at deployment.**

TL;DR

- A signed JWT proves who called an API. An Agent Manifest proves who the agent *was*, what it was *allowed to do*, how it was *built*, what it *decided*, and who *approved* it.
- Level 0 is software-only Ed25519 signing and runs anywhere with Python 3.11 or later. Hardware attestation (TPM 2.0, AMD SEV-SNP, Intel TDX, OPAQUE) is optional from Level 1 up.
- Install with `pip install "agent-manifest[cli]"` and verify your first manifest in under 15 minutes.

A signed JWT proves who called an API. An Agent Manifest proves who the agent **was**, what it was **allowed to do**, how it was **built**, what it **decided**, who **approved** it, and whether any of that changed between approval and execution.

```
pip install "agent-manifest[cli]"
```

```
manifest keygen -d ./keys/
manifest create config.json -o draft.json
manifest sign draft.json --key keys/private.hex -o signed.json
manifest verify signed.json   # VALID
```

## The agent attestation gap

Every entity in a modern enterprise has a verifiable identity. Users have X.509 certificates. Services have SPIFFE SVIDs. Containers have image digests. AI agents have none of these.

An agent calling a tool today presents no unforgeable proof of which system prompt defined its behavior, which model is running, which policy was approved, or whether a human reviewed any of it. This is not an authentication gap - agents can authenticate with tokens. It is an **attestation gap**: the inability to prove, to a third party who does not trust the operator, that the agent running right now is the agent that was approved.

Software-signed manifests do not close this gap. A privileged operator can replace a system prompt in memory after signing, swap a model version between approval and runtime, or forge a human-in-the-loop approval record. Hardware-attested manifests make these attacks impossible - the measurement happens in silicon before any user code runs and the signing key never leaves the TEE.

## How it works

```
Developer                 TEE                    Verifier
─────────                 ───                    ────────
Hash 10 artifacts   →   Measure in hardware  →  Verify against
Sign manifest       →   Seal signing key     →  attestation report
Publish to log      →   Return TRACE claim   →  VALID / MISMATCH
```

A verifying party who holds an Agent Manifest and its accompanying attestation report can prove - without trusting the operator - that a specific agent ran specific code under specific policy with specific tools, produced specific decisions, and received specific human oversight.

## The 10 attested artifacts

| #   | Artifact        | What it proves                                                       |
| --- | --------------- | -------------------------------------------------------------------- |
| 1   | System Prompt   | The exact prompt defining the agent's persona and safety constraints |
| 2   | Policy Bundle   | The Cedar/Rego/YAML governance rules in force                        |
| 3   | Tool Manifest   | Every tool schema and description the agent was authorized to call   |
| 4   | Model Identity  | Which model and version ran (binary hash for local, version for API) |
| 5   | RAG Corpus      | The knowledge base the agent was grounded on (Merkle root)           |
| 6   | Memory Baseline | Approved agent memory state with TTL-based re-approval               |
| 7   | Decision Trace  | Hardware-signed audit chain root for all agent decisions             |
| 8   | A2A Delegation  | Signed delegation chain from human principal to current agent        |
| 9   | Supply Chain    | Container digest, SLSA provenance, SBOM, MCP server supply chain     |
| 10  | HITL Approvals  | Hardware-signed human oversight records (EU AI Act Art. 14)          |

## Hardware providers

| Provider    | Platform                                 | Assurance                |
| ----------- | ---------------------------------------- | ------------------------ |
| TPM 2.0     | Any Azure/AWS/GCP VM with Trusted Launch | Medium                   |
| AMD SEV-SNP | Azure DCasv5, AWS C6a Nitro, GCP N2D     | High                     |
| Intel TDX   | Azure DCedsv5, GCP C3                    | High                     |
| OPAQUE      | OPAQUE Managed Runtime                   | Managed (chain-verified) |

Provider auto-selects based on available hardware: `OPAQUE → SEV-SNP → TDX → TPM → software`.

## Conformance levels

| Level   | Requirements                                     | Use case                                      |
| ------- | ------------------------------------------------ | --------------------------------------------- |
| Level 0 | Software signing, all artifact bindings          | Development, staging                          |
| Level 1 | + TEE attestation, `audit_key_sealed: true`      | Enterprise production, EU AI Act Art. 15      |
| Level 2 | + All 10 artifacts, HITL approvals, Phase 2 cMCP | Regulated industries, DORA                    |
| Level 3 | + ML-DSA-65, ML-KEM-768, SHAKE-256               | Sovereign, classified, long-horizon financial |

## Frequently asked questions

### What is an Agent Manifest?

An Agent Manifest is a cryptographically signed record that anchors the 10 artifacts defining an AI agent at deployment: system prompt, policy bundle, tool manifest, model identity, RAG corpus, memory baseline, decision trace, A2A delegation, supply chain, and HITL approvals. It lets a third party verify that the agent running now is the agent that was approved.

### How is an Agent Manifest different from a signed JWT?

A signed JWT proves who called an API. An Agent Manifest proves who the agent was, what it was allowed to do, how it was built, what it decided, who approved it, and whether any of that changed between approval and execution.

### What is the agent attestation gap?

Users have X.509 certificates, services have SPIFFE SVIDs, and containers have image digests, but AI agents have no unforgeable proof of which prompt, model, or policy defined their behavior. The attestation gap is the inability to prove, to a third party who does not trust the operator, that the running agent matches the approved one.

### Does Agent Manifest require special hardware?

No. Level 0 uses software-only Ed25519 signing and runs anywhere with Python 3.11 or later. Hardware attestation (Level 1 and above) is optional and supports TPM 2.0, AMD SEV-SNP, Intel TDX, and OPAQUE, auto-selected by available hardware.

### What are the conformance levels?

Level 0 is software signing with all artifact bindings. Level 1 adds TEE attestation with a sealed audit key. Level 2 adds all 10 artifacts, HITL approvals, and Phase 2 cMCP. Level 3 adds the post-quantum profile (ML-DSA-65, ML-KEM-768, SHAKE-256).

### Is Agent Manifest free and open source?

Yes. It is published on PyPI (`pip install agent-manifest`) and developed in the open at [github.com/agentrust-io/agent-manifest](https://github.com/agentrust-io/agent-manifest).

## Next steps

- [Getting started](https://manifest.agentrust-io.com/getting-started/index.md) - Level 0 in 15 minutes
- [Examples](https://github.com/agentrust-io/examples) - complete manifest JSON for Level 0 and Level 1
- [Specification](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.1.md) - 197 conformance tests across 5 modules
- [Architecture decisions](https://manifest.agentrust-io.com/adr/index.md) - rationale behind cryptographic design choices
