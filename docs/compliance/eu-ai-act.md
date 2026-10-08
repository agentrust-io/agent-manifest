# EU AI Act compliance mapping

This page is for compliance officers and auditors working with the EU AI Act. It goes article by article and says what evidence an Agent Manifest can provide for AI systems the Act classes as high-risk, and where it provides nothing. It is a reference map, not a statement that any system complies.

**Status:** GPAI model obligations apply since **August 2025**, and **Article 50 transparency duties since 2 August 2026** (see below: the manifest does not satisfy them). Under the current provisional legislative timeline (the digital omnibus amendments), high-risk AI system obligations are expected to apply from around **December 2027**, and AI systems embedded in regulated products from around **August 2028**. These dates are still going through the legislative process. Check them against the [official AI Act timeline](https://artificialintelligenceact.eu/implementation-timeline/) before relying on them. Obligations already in force today (e.g. DORA for financial entities, HIPAA for US healthcare) are unaffected by this timeline.

Everything on this page below Article 50 maps to the **high-risk** obligations, which are the deferred ones. Article 50 is the one in force now.

---

## Article 50  -  Transparency obligations *(in force since 2 August 2026)*

> *AI systems intended to interact directly with natural persons shall be designed so that the person is informed they are interacting with an AI system, unless obvious. Providers of systems generating synthetic content shall mark the output in a machine-readable form.*

**What agent-manifest provides: nothing yet.** We say this up front because Article 50 is the duty an auditor can hold a deployment to today, and a mapping page that left it out would look as if it were covered.

| Article 50 paragraph | Obligation | Status |
|----------------------|------------|--------|
| 50(1) | Inform persons they are interacting with an AI system | No manifest field. Disclosure is delivered at runtime; AGT's `agent_os.transparency` interceptor enforces it at the tool-call boundary. |
| 50(2) | Mark synthetic output as artificially generated, machine-readably | No manifest field. A mark any party can strip does not meet the requirement, so binding the mark to the attested agent that produced the output is the intended design. Not built. |
| 50(3) | Inform persons exposed to emotion recognition or biometric categorisation | No manifest field. Enforced at runtime by the same AGT interceptor. A manifest whose approved scope covers biometric tooling is evidence the deployment is in scope. |
| 50(4) | Deepfake and public-interest text disclosure | No manifest field. Same gap as 50(2). |

Article 50 applies regardless of whether the system is high-risk under Annex III. Do not present a manifest as Article 50 evidence.

---

## Article 9  -  Risk management system

> *Providers of high-risk AI systems shall establish a risk management system* that identifies and estimates known and foreseeable risks.

**What agent-manifest provides**

The manifest can record a person's risk rating for the agent (low, medium, high or critical), which parts of the agent that rating covers, and any conditions attached to the approval. The approver signs it with their own key, so any later change to the rating shows up. HITL ("human in the loop") means a named person has to approve.

The rating sits in `hitl_record.approvals[].approved_scope.risk_tier`. The requirement for human approval (`hitl_record.required`) is covered by the issuer's signature.

```json
{
  "hitl_record": {
    "required": true,
    "approvals": [{
      "approver_id": "mailto:risk-officer@example.com",
      "approved_scope": {
        "artifacts": ["tool_manifest", "policy_bundle"],
        "risk_tier": "high",
        "approval_duration_seconds": 7776000,
        "conditions": ["Processes financial decisions affecting natural persons"]
      }
    }]
  }
}
```

The signed manifest is one record within a risk management system. An auditor can verify that the assessment was made before deployment (manifest `issued_at`) and has not been altered since.

---

## Article 12  -  Record-keeping

> *High-risk AI systems shall automatically log events* to enable post-deployment review.

**What agent-manifest provides**

The manifest records a single fingerprint (the audit chain root) that sums up the agent's decision log when the manifest was issued. Given one decision and a short proof, an auditor can check that it was in the log behind that fingerprint, without seeing any other decisions.

??? info "Technical detail: the Merkle audit chain"
    Every manifest includes an `artifacts.decision_trace` section with a Merkle `audit_chain_root`. Each decision appended to the trace is a leaf in a tamper-evident Merkle tree. An auditor can present any decision and verify it was recorded before a given audit_chain_root, without access to any other decisions.

    The audit chain root is deterministic and reproducible: losing the chain does not lose the ability to verify past roots.

The manifest does not do the logging: the agent's runtime has to write the log, and a fingerprint cannot show that every event was written.

---

## Article 13  -  Transparency and provision of information to deployers

> *High-risk AI systems shall be designed so that their operation is sufficiently transparent* to enable deployers to interpret and use the system's output appropriately.

**What agent-manifest provides**

| Article 13 requirement | Manifest field |
|------------------------|----------------|
| Identity of the provider | `issuer` (SPIFFE URI of the signing authority) |
| Identity of the AI system | `agent_id` (SPIFFE URI of the agent role) |
| Model used | `artifacts.model_identity.provider`, `.model_id`, `.version` |
| System prompt used | `artifacts.system_prompt.hash` (SHA-256, content-addressed) |
| Tools the system can invoke | `artifacts.tool_manifest.tools[]` |

All fields are signed by the issuer key. A deployer can check the signed manifest and see exactly which model, prompt and tools were approved, without taking the agent's word for it. Confirming that the running agent matches still needs the deployer's own runtime values.

---

## Article 14  -  Human oversight

> *High-risk AI systems shall be designed so that they can be effectively overseen by natural persons during the period in which the AI system is in use.*

**What agent-manifest provides**

The manifest can carry signed records of a person approving the agent, in the `hitl_record` field:

```json
{
  "hitl_record": {
    "required": true,
    "approvals": [{
      "approval_id": "019236ab-0000-7000-8000-000000000031",
      "approver_id": "mailto:alice@example.com",
      "approver_identity_type": "email",
      "approver_role": "payments-security-officer",
      "approved_at": "2026-06-01T09:15:00Z",
      "approved_scope": {
        "artifacts": ["tool_manifest"],
        "risk_tier": "high",
        "approval_duration_seconds": 28800,
        "conditions": ["execute_payment", "submit_regulatory_filing"]
      },
      "approval_signature": "...",
      "approval_method": "hardware-key",
      "evidence_uri": "https://approvals.example.com/records/..."
    }]
  }
}
```

The signature is made over `{manifest_id, approved_at, approved_scope, approver_id}` by the approver's key. This proves:

- The holder of a trusted approver key approved this specific agent (whether a person reviewed it first is an organizational control the signature cannot show)
- The approval covers only the declared scope
- The approval has a bounded validity window
- The approval cannot be forged without the approver's key

**Conformance levels and Article 14:** Article 14 requires effective human oversight of high-risk systems; it says nothing about Agent Manifest levels. A HITL record with verified approvals is evidence of how oversight was designed and exercised, and hardware attestation (Level 1 and above) adds evidence that the approved configuration is what ran. Neither shows on its own that oversight was effective.

---

## Article 17  -  Quality management system

> *Providers shall put in place a quality management system* that ensures compliance with this Regulation.

**What agent-manifest provides**

The manifest fixes the fingerprints (hashes) of the model, the prompt and the tool catalog when it is issued, which gives a quality record. Any deviation from the approved configuration produces a manifest verification failure (`MISMATCH` result), giving the quality management system a reliable signal that the deployed agent differs from the approved one.

The issuer key rotation procedure (see [Tutorial: Revocation and key rotation](../tutorials/revocation-and-key-rotation.md)) documents the process for managing keys, which can feed the quality management system's documentation.

---

## Conformance level guidance for high-risk AI

A conformance level says how much a manifest covers and how strongly it is backed. Levels are defined in section 8.1 of the specification. A higher level does not simply mean better hardware: the level says what is bound and attested, and the choice of TEE (a hardware-isolated area that can prove what is running in it) sits inside Level 1.

| Conformance level | What it requires | Recommended for |
|-------------------|------------------|-----------------|
| 0: Software-only | All artifact bindings, standard crypto, transparency log publication. No TEE. | Development, staging, non-regulated systems |
| 1: TEE-attested | Level 0 plus a TEE attestation block, `audit_key_sealed: true`, and a hardware-verified `container_image_digest`. TPM 2.0, AMD SEV-SNP and Intel TDX all satisfy this; they differ in the strength of the root, not in the level. | Enterprise production |
| 2: Full stack | Level 1 plus all 10 artifacts bound, HITL approvals present, delegation chain for multi-agent, Phase 2 cMCP, `minimum_retention_days >= 180`, and a declared drift policy. | High-risk AI under Article 6(2), Annex III |
| 3: Post-quantum | Level 2 plus ML-DSA-65, ML-KEM-768, SHAKE-256, and a private Sigstore instance supporting ML-DSA-65. | Sovereign, classified, long-horizon financial |

For high-risk AI systems under Article 6(2), Annex III, **Level 2 or above is recommended**, because Article 12 record-keeping and Article 14 human oversight need the artifacts that Level 2 requires to be bound rather than merely present. Level 1 is a reasonable interim where the full artifact set is not yet in place, provided a compensating HITL control is documented.

Within Level 1, the root of trust (whose signing key the hardware report finally rests on) still changes what a verifier can conclude: SEV-SNP and TDX attest a confidential VM directly, while a TPM 2.0 quote attests the boot chain of a VM the host can still see into. Azure confidential VMs are a third case, vTPM-rooted rather than direct-silicon, and are documented in `LIMITATIONS.md`.

---

## Summary table

| EU AI Act Article | Obligation | agent-manifest capability |
|-------------------|------------|---------------------------|
| Article 50 *(in force)* | Transparency and synthetic-content marking | **None.** Runtime disclosure via AGT; marking not built |
| Article 9 | Risk management record | `approved_scope.risk_tier` (approver-signed) |
| Article 12 | Automatic logging | Merkle `audit_chain_root` |
| Article 13 | Transparency to deployers | Signed identity + artifact hashes |
| Article 14 | Human oversight | `hitl_record` (signed, scoped) |
| Article 17 | Quality management | Signed artifact bindings; mismatch detection |

---

*This mapping is provided as reference material. It does not constitute legal advice. Consult your legal and compliance teams before making compliance claims.*
