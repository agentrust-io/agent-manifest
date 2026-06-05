# DORA compliance mapping

DORA (Digital Operational Resilience Act, Regulation (EU) 2022/2554) applied to EU financial entities from **January 17, 2025**. This page maps agent-manifest capabilities to DORA ICT risk requirements for financial services firms deploying AI agents.

---

## Article 8 — Identification of ICT risks

> *Financial entities shall identify all sources of ICT risk* and document information assets and related dependencies.

**What agent-manifest provides**

A signed manifest is a machine-readable ICT asset record. It documents:

- The AI agent's identity (`agent_id`, SPIFFE URI)
- The model version in use (`artifacts.model_identity`)
- The system prompt in use (`artifacts.system_prompt.hash`)
- The tools the agent can invoke (`artifacts.tool_manifest.tools[]`)
- The cryptographic profile (`crypto_profile`: Ed25519, ML-DSA-65 hybrid)

Every field is signed by the issuer key, making the record tamper-evident. An inventory sweep can verify that all deployed agents have valid, unexpired manifests and produce a signed asset register.

---

## Article 11 — ICT business continuity

> *Financial entities shall put in place ICT business continuity policies, plans, and procedures.*

**What agent-manifest provides**

**Key rotation:** The [Revocation and key rotation tutorial](../tutorials/revocation.md) documents a zero-downtime rotation procedure. The procedure allows issuing new manifests under a new signing key without interrupting agent operations, satisfying DORA's requirement for continuity under ICT disruption.

**Revocation:** The `FileCRL` component provides an append-only, signed certificate revocation list. A compromised agent can be revoked in under one second by appending a signed `SignedRevocationRecord`. All verifiers checking the CRL endpoint immediately begin rejecting the revoked agent.

**Recovery time objective (RTO):** Key rotation and agent reissuance can be completed in under five minutes using the runbook. The revocation mechanism has no single point of failure — the CRL file can be served from any static file host.

---

## Article 17 — ICT-related incident classification

> *Financial entities shall classify ICT-related incidents and determine their impact.*

**What agent-manifest provides**

When an ICT incident involves an AI agent (e.g., an agent behaves unexpectedly, is compromised, or is suspected of data exfiltration), the manifest provides:

- **Exact configuration at time of incident** — model version, prompt hash, tool catalog hash, all signed and timestamped
- **Authorisation chain** — who issued the manifest, who approved deployment (HITL record)
- **Merkle audit root** — allows verifying that specific decisions were recorded before the incident, without replaying the full audit log

This evidence satisfies DORA's requirement to document the "scope and nature" of an incident and supports the incident timeline required under Article 19 reporting.

---

## Article 25 — Testing of ICT tools and systems

> *Financial entities shall establish a comprehensive digital operational resilience testing programme.*

**What agent-manifest provides**

Conformance levels provide a testability hierarchy:

| Conformance level | Test coverage | DORA relevance |
|-------------------|--------------|----------------|
| 0 — Software only | Manifest schema validation, signature verification | Baseline; insufficient for production financial systems |
| 1 — TPM | + TPM attestation verification | Acceptable for internal tools |
| 2 — SEV-SNP / TDX | + hardware enclave report verification | Recommended for customer-facing financial AI |
| 3 — Managed TEE | + managed attestation authority | Required for critical ICT third-party services |

The test suite (`pytest --cov=agent_manifest --cov-fail-under=80`) runs all 197 conformance-level tests in CI, producing a verifiable coverage record. This record can be cited as evidence in DORA testing documentation.

---

## RTS requirements — key management controls

The DORA Regulatory Technical Standards (RTS) require documented key management controls for ICT systems. Agent-manifest satisfies the following RTS controls:

| RTS control | Mechanism |
|-------------|-----------|
| Key generation in a secure environment | `generate_ed25519()` / `generate_ml_dsa_65()` produce keys in-process; production deployments use HSM-backed generation |
| Key storage separated from signing operations | Issuer key never stored in the manifest; only the public key is embedded |
| Key rotation procedure | Documented in [Tutorial: Revocation and key rotation](../tutorials/revocation.md) |
| Key revocation mechanism | `FileCRL` + `.well-known/agent-manifest/revocation` endpoint |
| Audit trail of key usage | Every manifest signature is a timestamped key-use record |

---

## Summary table

| DORA Article | Obligation | agent-manifest capability |
|--------------|------------|---------------------------|
| Article 8 | ICT risk identification | Signed manifest as tamper-evident ICT asset record |
| Article 11 | Business continuity | Zero-downtime key rotation; append-only CRL revocation |
| Article 17 | Incident classification | Exact configuration + authorisation chain at incident time |
| Article 25 | Resilience testing | Conformance level test suite (197 tests, CI-verified) |
| RTS key management | Key lifecycle controls | Generation, rotation, revocation, audit trail |

---

*This mapping is provided as reference material. It does not constitute legal advice. Consult your legal and compliance teams before making compliance claims.*
