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
manifest verify signed.json --public-key keys/public.hex   # VALID
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

A verifying party who holds an Agent Manifest and its accompanying attestation report can prove - without trusting the operator - that a specific agent started with specific code, policy, tools, audit-chain baseline, and human oversight. Runtime evidence shows what happened after that point and is verified separately.

## The 10 attested artifacts

| #   | Artifact              | What it proves                                                                                     |
| --- | --------------------- | -------------------------------------------------------------------------------------------------- |
| 1   | System Prompt         | The exact prompt defining the agent's persona and safety constraints                               |
| 2   | Policy Bundle         | The Cedar/Rego/YAML governance rules in force                                                      |
| 3   | Tool Manifest         | Every tool schema and description the agent was authorized to call                                 |
| 4   | Model Identity        | Which model and version ran (binary hash for local, version for API)                               |
| 5   | RAG Corpus            | The knowledge base the agent was grounded on (Merkle root)                                         |
| 6   | Memory Baseline       | Approved agent memory state with TTL-based re-approval                                             |
| 7   | Decision-log baseline | Audit-chain root current when the manifest is issued; later decisions are separate linked evidence |
| 8   | A2A Delegation        | Signed delegation chain from human principal to current agent                                      |
| 9   | Supply Chain          | Container digest, SLSA provenance, SBOM, MCP server supply chain                                   |
| 10  | HITL Approvals        | Hardware-signed human oversight records (EU AI Act Art. 14)                                        |

## Hardware providers

| Provider    | Platform                                 | Assurance                |
| ----------- | ---------------------------------------- | ------------------------ |
| TPM 2.0     | Any Azure/AWS/GCP VM with Trusted Launch | Medium                   |
| AMD SEV-SNP | Azure DCasv5, AWS C6a Nitro, GCP N2D     | High                     |
| Intel TDX   | Azure DCedsv5, GCP C3                    | High                     |
| OPAQUE      | OPAQUE Managed Runtime                   | Managed (chain-verified) |

Provider auto-selects based on available hardware: `OPAQUE → SEV-SNP → TDX → TPM → software`.

## Conformance levels

| Level   | Requirements                                     | Use case                                                |
| ------- | ------------------------------------------------ | ------------------------------------------------------- |
| Level 0 | Software signing, all artifact bindings          | Development, staging                                    |
| Level 1 | + TEE attestation, `audit_key_sealed: true`      | Enterprise production; EU AI Act Art. 15 from ~Dec 2027 |
| Level 2 | + All 10 artifacts, HITL approvals, Phase 2 cMCP | Regulated industries, DORA                              |
| Level 3 | + ML-DSA-65, ML-KEM-768, SHAKE-256               | Sovereign, classified, long-horizon financial           |

## Frequently asked questions

### What is an Agent Manifest?

An Agent Manifest is a cryptographically signed record that anchors the 10 artifacts defining an AI agent at deployment: system prompt, policy bundle, tool manifest, model identity, RAG corpus, memory baseline, decision-log baseline, A2A delegation, supply chain, and HITL approvals. It lets a third party verify that the agent running now is the agent that was approved. It does not claim that later runtime decisions existed at deployment time: those are separate TRACE or OCSF records joined back to the manifest.

### How is an Agent Manifest different from a signed JWT?

A signed JWT proves who called an API. An Agent Manifest proves who the agent was, what it was allowed to do, how it was built, which audit-chain baseline it started from, who approved it, and whether the deployment configuration changed before execution.

### Why not specify it as a JWT or JOSE profile?

Because of what comparable standards chose, not because JWT is incapable. The IETF already picked the JWT/CWT route for attestation *tokens*: EAT ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)) even supports nested tokens and detached claim sets. That is the right shape for "who is calling, right now," and an EAT is a valid input to a manifest's attestation block.

Every multi-artifact provenance standard with a transparency log went the other way. SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html)), the closest analog to Agent Manifest, mandates COSE_Sign1 signed statements. DSSE, the envelope behind in-toto and SLSA, rejected a JWS profile in writing, citing implementation hazards and canonicalization as attack surface. C2PA uses COSE_Sign1 inside a JUMBF container.

An Agent Manifest is that second kind of object: ten artifacts, several independent signers, hardware-report binding, a 90-day life, and a log receipt attached after signing. So the layering is EAT and JWT for the attestation-token input, and a signed document for the manifest. The two compose. See [ADR-0011](https://manifest.agentrust-io.com/adr/0011-signature-envelope/index.md) for the full argument. The envelope moves to COSE_Sign1 in spec v0.2 to align with SCITT; v0.1 manifests keep verifying unchanged.

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
- [Specification](https://manifest.agentrust-io.com/spec/agent-manifest-v0.2/index.md) - 197 conformance tests across 5 modules
- [Architecture decisions](https://manifest.agentrust-io.com/adr/index.md) - rationale behind cryptographic design choices
