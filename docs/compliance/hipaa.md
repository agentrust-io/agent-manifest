# HIPAA compliance mapping

HIPAA's Security Rule (45 CFR Part 164) applies to AI agents that access, process, or transmit electronic protected health information (ePHI). This page is for privacy and security officers at US healthcare organisations and their vendors. It maps the HIPAA Security Rule safeguards most relevant to AI agents to the evidence an Agent Manifest can provide. It is a reference map, not a statement that any system complies.

---

## § 164.312(a)(1)  -  Access control

> *Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights.*

**What agent-manifest provides**

When one agent hands work to another, the manifest's delegation chain records each handover and what it allowed, and each step is signed. Each hop documents:

- Who delegated (principal SPIFFE URI)
- What scope was granted (`tools`, `data_classifications`)
- Whether human approval was required

An agent attempting to access ePHI beyond its declared scope produces a `SCOPE_EXCEEDED` verification failure. The verifier enforces scope at runtime without relying on the agent's self-report.

```json
{
  "delegation_chain": [{
    "hop": 0,
    "principal_type": "system",
    "principal_id": "spiffe://trust.example/system/ehr-coordinator",
    "delegated_at": "2026-06-12T09:00:00Z",
    "scope_grant": {
      "tools": ["org.example.ehr.read_patient_record"],
      "data_classifications": ["restricted"],
      "max_delegation_depth": 0
    },
    "delegation_signature": "..."
  }]
}
```

Map ePHI to the `restricted` data classification. The `max_delegation_depth: 0` grant means no sub-agent can be delegated PHI access at all; pair it with `hitl_record.required: true` so PHI access requires a matching HITL approval record.

---

## § 164.312(b)  -  Audit controls

> *Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.*

**What agent-manifest provides**

The manifest holds one fingerprint that sums up the agent's decision log, so later changes to the log can be detected. The field is `artifacts.decision_trace.audit_chain_root`, the root of a Merkle tree (a structure of nested hashes) of agent decisions. Properties relevant to HIPAA audit controls:

- **Tamper-evident**: each appended decision extends the chain root; removing or altering a decision invalidates all subsequent roots
- **Selective disclosure**: a specific decision can be proven present in the chain without disclosing other decisions (Merkle inclusion proof)
- **Time-ordered**: decisions are appended in order; the chain root advances monotonically
- **Signed**: the chain root is included in the signed manifest, binding the audit record to the authorised agent identity

For HIPAA audit log retention (minimum six years), the chain root provides a compact, verifiable summary. The full decision log can be archived separately; the chain root proves the archive has not been altered.

---

## § 164.312(c)(1)  -  Integrity

> *Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.*

**What agent-manifest provides**

Every manifest field is protected by an Ed25519 + ML-DSA-65 hybrid signature (see [ADR-0005](../adr/0005-ml-dsa-hybrid-signature.md)). The signature covers the canonicalised JSON of the entire manifest (RFC 8785). Any change to any field (model version, prompt hash, tool catalog, delegation chain, HITL approval) makes the signature check fail.

ML-DSA-65 (NIST FIPS 204) is a signature designed to resist future quantum computers, which supports HIPAA's requirement that integrity mechanisms remain effective over the six-year retention period.

---

## § 164.308(a)(5)  -  Security awareness and training

> *Implement procedures for guarding against, detecting, and reporting malicious software.*

**What agent-manifest provides**

The HITL (human-in-the-loop) approval mechanism provides documented human oversight for AI agent deployment. A signed approval record proves:

- A named approver reviewed the agent before it accessed ePHI
- The approval was time-bounded (typically to a single session or shift)
- The approval covered only the declared scope

The approver's key is separate from the issuer key, ensuring that a compromised issuer cannot retroactively forge approvals. See [Tutorial: HITL approval workflows](../tutorials/hitl-approval-workflows.md) for implementation details.

---

## § 164.308(a)(1)  -  Security management process

> *Implement policies and procedures to prevent, detect, contain, and correct security violations.*

**What agent-manifest provides**

**Detection:** A verification failure (any non-`VALID` result) is a security signal. Collect verification failures by agent identity in your SIEM (security event monitoring system) to detect unusual patterns.

**Containment:** Revoke the agent's manifest via the CRL endpoint. Propagation to all verifiers checking the endpoint is immediate (next poll cycle, typically <30s).

**Correction:** Re-issue the manifest under a new signing key after rotating the compromised key. The key rotation procedure is documented in the [Revocation and key rotation tutorial](../tutorials/revocation-and-key-rotation.md).

---

## Summary table

| HIPAA Security Rule | Safeguard | agent-manifest capability |
|---------------------|-----------|---------------------------|
| § 164.312(a)(1) | Access control | Signed delegation chain with scope enforcement |
| § 164.312(b) | Audit controls | Merkle audit chain root (tamper-evident, selective disclosure) |
| § 164.312(c)(1) | Integrity | Ed25519 + ML-DSA-65 hybrid signature over RFC 8785 canonical JSON |
| § 164.308(a)(5) | Human oversight | HITL approval record (signed, scoped, time-bounded) |
| § 164.308(a)(1) | Security management | Revocation (<1s), key rotation, verification failure as security signal |

---

*This mapping is provided as reference material. It does not constitute legal advice. Consult your legal and compliance teams before making compliance claims.*
