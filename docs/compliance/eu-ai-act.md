# EU AI Act compliance mapping

This page maps agent-manifest capabilities to EU AI Act obligations for high-risk AI systems. It is written for compliance officers and auditors, not developers.

**Status:** GPAI model obligations apply since **August 2025**. Under the current provisional legislative timeline (the digital omnibus amendments), high-risk AI system obligations are expected to apply from around **December 2027**, and AI systems embedded in regulated products from around **August 2028**. These dates remain subject to the legislative process — verify against the [official AI Act timeline](https://artificialintelligenceact.eu/implementation-timeline/) before relying on them. Obligations already in force today (e.g. DORA for financial entities, HIPAA for US healthcare) are unaffected by this timeline.

---

## Article 9  -  Risk management system

> *Providers of high-risk AI systems shall establish a risk management system* that identifies and estimates known and foreseeable risks.

**What agent-manifest provides**

The manifest's `risk_classification` field carries a structured risk assessment: category, rationale, and the conformance level required for deployment. This field is signed as part of the manifest, making it tamper-evident.

```json
{
  "risk_classification": {
    "category": "high",
    "rationale": "Processes financial decisions affecting natural persons",
    "required_conformance_level": 2
  }
}
```

The signed manifest is the risk management record. An auditor can verify that the classification was made before deployment (manifest `issued_at`) and has not been altered since.

---

## Article 12  -  Record-keeping

> *High-risk AI systems shall automatically log events* to enable post-deployment review.

**What agent-manifest provides**

Every manifest includes an `artifacts.decision_trace` section with a Merkle `audit_chain_root`. Each decision appended to the trace is a leaf in a tamper-evident Merkle tree. An auditor can present any decision and verify it was recorded before a given audit_chain_root  -  without access to any other decisions.

The audit chain root is deterministic and reproducible: losing the chain does not lose the ability to verify past roots.

---

## Article 13  -  Transparency and provision of information to deployers

> *High-risk AI systems shall be designed so that their operation is sufficiently transparent* to enable deployers to interpret and use the system's output appropriately.

**What agent-manifest provides**

| Article 13 requirement | Manifest field |
|------------------------|----------------|
| Identity of the provider | `issuer` (SPIFFE URI of the signing authority) |
| Identity of the AI system | `agent_id` (SPIFFE URI of the agent role) |
| Model used | `artifacts.model_identity.provider`, `.model_family`, `.version` |
| System prompt used | `artifacts.system_prompt.hash` (SHA-256, content-addressed) |
| Tools the system can invoke | `artifacts.tool_manifest.tools[]` |

All fields are signed by the issuer key. A deployer can verify the signed manifest and confirm exactly what model, prompt, and tools are in use  -  without trusting the agent's self-report.

---

## Article 14  -  Human oversight

> *High-risk AI systems shall be designed so that they can be effectively overseen by natural persons during the period in which the AI system is in use.*

**What agent-manifest provides**

The `hitl_approval` field records a human approval event:

```json
{
  "hitl_approval": {
    "approved_at": "2026-06-01T09:15:00Z",
    "approver_id": "mailto:alice@example.com",
    "approved_scope": ["execute_payment", "submit_regulatory_filing"],
    "approval_expires_at": "2026-06-01T17:00:00Z",
    "signature": "..."
  }
}
```

The signature is made over `{manifest_id, approved_at, approved_scope, approver_id}` by the approver's key. This proves:

- A named human reviewed and approved this specific agent
- The approval covers only the declared scope
- The approval has a bounded validity window
- The approval cannot be forged without the approver's key

**Conformance level requirement:** Article 14 HITL requires Level 1+ for high-risk AI systems. Level 0 (software-only) manifests without hardware attestation must not be deployed in high-risk contexts without an accompanying HITL record.

---

## Article 17  -  Quality management system

> *Providers shall put in place a quality management system* that ensures compliance with this Regulation.

**What agent-manifest provides**

Signed artifact bindings create a quality record: the model hash, prompt hash, and tool catalog hash are locked at issuance. Any deviation from the approved configuration produces a manifest verification failure (`MISMATCH` result), giving the quality management system a reliable signal that the deployed agent differs from the approved one.

The issuer key rotation procedure (see [Tutorial: Revocation and key rotation](../tutorials/revocation.md)) documents the governance process for key management, satisfying the quality management system's documentation requirement.

---

## Conformance level guidance for high-risk AI

| Conformance level | Hardware root of trust | Recommended for |
|-------------------|----------------------|-----------------|
| 0  -  Software only | None | Development, low-risk systems |
| 1  -  TPM | TPM 2.0 | General enterprise deployment |
| 2  -  SEV-SNP / TDX | AMD SEV-SNP or Intel TDX | High-risk AI under Article 6 |
| 3  -  Managed TEE | OPAQUE / Cloud HSM | Critical infrastructure, financial services |

For high-risk AI systems under Article 6(2), Annex III, **Level 2 or above is recommended**. Level 1 is acceptable where hardware TEE deployment is not yet feasible, provided a compensating HITL control is in place.

---

## Summary table

| EU AI Act Article | Obligation | agent-manifest capability |
|-------------------|------------|---------------------------|
| Article 9 | Risk management record | `risk_classification` (signed) |
| Article 12 | Automatic logging | Merkle `audit_chain_root` |
| Article 13 | Transparency to deployers | Signed identity + artifact hashes |
| Article 14 | Human oversight | `hitl_approval` (signed, scoped) |
| Article 17 | Quality management | Signed artifact bindings; mismatch detection |

---

*This mapping is provided as reference material. It does not constitute legal advice. Consult your legal and compliance teams before making compliance claims.*
