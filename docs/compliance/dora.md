# DORA compliance mapping

DORA (Digital Operational Resilience Act, Regulation (EU) 2022/2554) applied to EU financial entities from **January 17, 2025**. This page is for compliance and risk teams at EU financial firms that deploy AI agents. It maps DORA's requirements on ICT (information and communication technology) risk to the evidence an Agent Manifest can provide. It is a reference map, not a statement that any system complies.

---

## Article 8  -  Identification of ICT risks

> *Financial entities shall identify all sources of ICT risk* and document information assets and related dependencies.

**What agent-manifest provides**

A signed manifest is an asset record that software can read. It documents:

- The AI agent's identity (`agent_id`, SPIFFE URI)
- The model version in use (`artifacts.model_identity`)
- The system prompt in use (`artifacts.system_prompt.hash`)
- The tools the agent can invoke (`artifacts.tool_manifest.tools[]`)
- The cryptographic profile (`crypto_profile`: Ed25519, ML-DSA-65 hybrid)

Every field is signed by the issuer key, so any change to the record shows up. An inventory sweep can verify that all deployed agents have valid, unexpired manifests and produce a signed asset register.

---

## Article 11  -  ICT business continuity

> *Financial entities shall put in place ICT business continuity policies, plans, and procedures.*

**What agent-manifest provides**

**Key rotation:** The [Revocation and key rotation tutorial](../tutorials/revocation-and-key-rotation.md) documents a rotation procedure that issues new manifests under a new signing key without stopping agents. It provides evidence relevant to DORA's continuity requirements; it is not a continuity plan.

**Revocation:** The `FileCRL` component provides an append-only, signed revocation list (a published list of manifests that are no longer trusted). To revoke a compromised agent, append a signed `SignedRevocationRecord`. A verifier using the same `FileCRL` object rejects the agent on its next check. Other verifiers see the revocation when they next reload the list or query its endpoint, so how fast it reaches them depends on how often they refresh; the SDK sets no refresh interval. `FileCRL` is a development store, and production needs a database-backed store (ADR-0007).

**Recovery time objective (RTO):** Key rotation and agent reissuance follow the runbook in the tutorial. The SDK publishes no timing for this, so measure your own recovery time against the runbook. The CRL file can be served from any static file host.

---

## Article 17  -  ICT-related incident classification

> *Financial entities shall classify ICT-related incidents and determine their impact.*

**What agent-manifest provides**

When an ICT incident involves an AI agent (e.g., an agent behaves unexpectedly, is compromised, or is suspected of data exfiltration), the manifest provides:

- **Exact configuration at time of incident**: model version, prompt hash, tool catalog hash, all signed and timestamped
- **Authorisation chain**: who issued the manifest, who approved deployment (HITL record)
- **Merkle audit root** (one fingerprint summing up the decision log): allows verifying that specific decisions were recorded before the incident, without replaying the full audit log

This evidence helps document the "scope and nature" of an incident as DORA requires, and supports the incident timeline required under Article 19 reporting.

---

## Article 25  -  Testing of ICT tools and systems

> *Financial entities shall establish a comprehensive digital operational resilience testing programme.*

**What agent-manifest provides**

Conformance levels (how much a manifest covers and how strongly it is backed) give a ladder of things to test:

| Conformance level (spec section 8.1) | What the level adds | Relevance |
|-------------------|--------------|----------------|
| 0: Software-only | All artifact bindings, standard crypto profile, transparency log publication | Baseline for development and non-regulated use |
| 1: TEE-attested | + TEE attestation block, sealed audit key, container image digest verified by hardware | Enterprise production |
| 2: Full stack | + all 10 artifacts bound, HITL approvals, delegation chain, cMCP for all MCP servers, at least 180 days of log retention, a drift policy | Provides evidence relevant to DORA Art. 9 for regulated industries (spec section 8.1) |
| 3: Post-quantum | + ML-DSA-65 signatures, ML-KEM-768 key exchange, SHAKE-256 hashing | Deployments with long-horizon sensitivity |

CI runs the full test suite with `pytest --cov=agent_manifest --cov-fail-under=80`, including the five conformance modules (AM-BIND, AM-CRYPTO, AM-ATTEST, AM-VERIFY, AM-COMPAT), and produces a verifiable coverage record that can be cited in DORA testing documentation. The specification defines a 197-test conformance suite (section 8.2); the implemented module tests do not yet map one to one onto that list.

---

## RTS requirements  -  key management controls

The DORA Regulatory Technical Standards (RTS, the detailed rules under DORA) require documented controls over signing keys for ICT systems. Agent-manifest provides mechanisms for the following RTS controls:

| RTS control | Mechanism |
|-------------|-----------|
| Key generation in a secure environment | `generate_ed25519()` / `generate_ml_dsa_65()` produce keys in-process; production deployments use HSM-backed generation |
| Key storage separated from signing operations | Issuer key never stored in the manifest; only the public key is embedded |
| Key rotation procedure | Documented in [Tutorial: Revocation and key rotation](../tutorials/revocation-and-key-rotation.md) |
| Key revocation mechanism | `FileCRL` + `.well-known/agent-manifest/revocation` endpoint |
| Audit trail of key usage | Every manifest signature is a timestamped key-use record |

---

## Summary table

| DORA Article | Obligation | agent-manifest capability |
|--------------|------------|---------------------------|
| Article 8 | ICT risk identification | Signed manifest as tamper-evident ICT asset record |
| Article 11 | Business continuity | Evidence relevant to continuity: key rotation runbook, append-only CRL revocation |
| Article 17 | Incident classification | Exact configuration + authorisation chain at incident time |
| Article 25 | Resilience testing | Conformance module tests and the full test suite, run in CI with a coverage gate |
| RTS key management | Key lifecycle controls | Generation, rotation, revocation, audit trail |

---

*This mapping is provided as reference material. It does not constitute legal advice. Consult your legal and compliance teams before making compliance claims.*
