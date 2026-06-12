# GDPR compliance mapping

The General Data Protection Regulation (GDPR) applies to AI agents that process personal data of EU residents. This page maps agent-manifest capabilities to the accountability and processing control obligations most relevant to AI agent deployments.

---

## Article 5(2)  -  Accountability principle

> *The controller shall be responsible for, and be able to demonstrate compliance with, paragraph 1 (the principles).*

**What agent-manifest provides**

A signed manifest is a verifiable accountability record for an AI agent. It proves who issued the agent (`issuer` SPIFFE URI), what configuration it was authorised to run, and who approved deployment (HITL record). Because the manifest is signed, the controller can demonstrate these facts without relying on self-reported agent state.

A manifest store (database, `.well-known` endpoint, or immutable log) provides an auditable history of every agent version that processed personal data, satisfying the controller's obligation to demonstrate compliance on request.

---

## Article 25  -  Data protection by design and by default

> *The controller shall implement appropriate technical and organisational measures designed to implement the data-protection principles in an effective manner.*

**What agent-manifest provides**

**Attestation level as a design control:** The manifest's conformance level is a measurable design control. An organisation can define a policy that agents processing personal data must be Level 2+ (SEV-SNP or TDX). Manifests at Level 0 or 1 are rejected by the verifier in personal-data contexts.

**Scope-limited delegation:** The delegation chain narrows scope at each hop. An orchestrator agent can delegate to a sub-agent with an explicit `data_classifications` scope grant, ensuring the sub-agent can only access data classes it was explicitly authorised for.

```json
{
  "scope_grant": {
    "tools": ["org.example.research.search_anonymised_records"],
    "data_classifications": ["internal"],
    "max_delegation_depth": 0
  }
}
```

(The spec's `data_classifications` values are `public`, `internal`, `confidential`, and `restricted`; map anonymised datasets to the lowest classification your policy allows.)

The verifier rejects any manifest where the effective scope exceeds what the delegation chain granted.

---

## Article 30  -  Records of processing activities

> *Each controller shall maintain a record of processing activities under its responsibility.*

**What agent-manifest provides**

The manifest is a record of processing intent  -  it documents what the agent was configured to do at the time of issuance. Fields that are relevant to Article 30 records:

| Article 30 requirement | Manifest field |
|------------------------|----------------|
| Purposes and legal basis of the processing | `data_scope.legal_basis`, `data_scope.dpia_reference` (signed) |
| Categories of personal data | `data_scope.personal_data_categories` (signed) |
| Recipients | `issuer`, `delegation_chain[].principal_id` |
| Where possible, time limits for erasure | `expires_at` (manifest validity window) |
| Where possible, security measures | `crypto_profile`, `attestation.level` |

The manifest's `issued_at` / `expires_at` pair documents the period during which the agent was authorised to process. A manifest that has expired and been re-issued creates a timestamped version history suitable for Article 30 records.

---

## Article 32  -  Security of processing

> *The controller and processor shall implement appropriate technical and organisational measures to ensure a level of security appropriate to the risk.*

**What agent-manifest provides**

| Article 32 measure | Mechanism |
|-------------------|-----------|
| Pseudonymisation and encryption | Not directly provided; manifest documents the agent's encryption capabilities via `artifacts` |
| Ability to ensure ongoing confidentiality | Attestation report (Level 2+) proves the agent runs in a hardware-isolated enclave |
| Ability to restore availability | Key rotation runbook; revocation with <1s propagation |
| Process for regular testing | 197-test suite, CI-enforced; conformance level test distribution documented in ADR-0008 |
| Integrity of systems | ML-DSA-65 + Ed25519 hybrid signatures; tamper evidence on every field |

---

## Summary table

| GDPR Article | Obligation | agent-manifest capability |
|--------------|------------|---------------------------|
| Article 5(2) | Accountability | Signed, verifiable record of who issued and authorised the agent |
| Article 25 | Data protection by design | Attestation level as policy-enforced design control; scope-limited delegation |
| Article 30 | Records of processing | Manifest as timestamped record of processing intent and scope |
| Article 32 | Security of processing | Hybrid signatures; hardware attestation; key rotation; CI test coverage |

---

*This mapping is provided as reference material. It does not constitute legal advice. Consult your legal and compliance teams before making compliance claims.*
