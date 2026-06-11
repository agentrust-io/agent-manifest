# HIPAA compliance mapping

HIPAA's Security Rule (45 CFR Part 164) applies to AI agents that access, process, or transmit electronic protected health information (ePHI). This page maps agent-manifest capabilities to the Security Rule safeguards most relevant to AI agent deployments.

---

## § 164.312(a)(1) — Access control

> *Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights.*

**What agent-manifest provides**

The manifest's delegation chain is a cryptographically signed access control record. Each hop documents:

- Who delegated (principal SPIFFE URI)
- What scope was granted (`tools`, `data_classifications`)
- Whether human approval was required

An agent attempting to access ePHI beyond its declared scope produces a `SCOPE_EXCEEDED` verification failure. The verifier enforces scope at runtime without relying on the agent's self-report.

```json
{
  "delegation_chain": [{
    "hop": 0,
    "principal_id": "spiffe://trust.example/system/ehr-coordinator",
    "scope_grant": {
      "tools": ["read_patient_record"],
      "data_classifications": ["phi"],
      "max_delegation_depth": 0,
      "approval_required": true
    },
    "signature": "..."
  }]
}
```

The `approval_required: true` field means no sub-agent can be delegated access to PHI without a matching HITL approval record.

---

## § 164.312(b) — Audit controls

> *Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.*

**What agent-manifest provides**

The `artifacts.decision_trace.audit_chain_root` field is the root of a Merkle tree of agent decisions. Properties relevant to HIPAA audit controls:

- **Tamper-evident**: each appended decision extends the chain root; removing or altering a decision invalidates all subsequent roots
- **Selective disclosure**: a specific decision can be proven present in the chain without disclosing other decisions (Merkle inclusion proof)
- **Time-ordered**: decisions are appended in order; the chain root advances monotonically
- **Signed**: the chain root is included in the signed manifest, binding the audit record to the authorised agent identity

For HIPAA audit log retention (minimum six years), the chain root provides a compact, verifiable summary. The full decision log can be archived separately; the chain root proves the archive has not been altered.

---

## § 164.312(c)(1) — Integrity

> *Implement policies and procedures to protect electronic protected health information from improper alteration or destruction.*

**What agent-manifest provides**

Every manifest field is protected by an Ed25519 + ML-DSA-65 hybrid signature (see [ADR-0005](../adr/0005-ml-dsa-hybrid-signature.md)). The signature covers the canonicalised JSON of the entire manifest (RFC 8785). Any alteration to any field — model version, prompt hash, tool catalog, delegation chain, HITL approval — produces a signature verification failure.

ML-DSA-65 (NIST FIPS 204) provides post-quantum signature security, satisfying HIPAA's requirement that integrity mechanisms remain effective over the six-year retention period.

---

## § 164.308(a)(5) — Security awareness and training

> *Implement procedures for guarding against, detecting, and reporting malicious software.*

**What agent-manifest provides**

The HITL approval mechanism provides documented human oversight for AI agent deployment. A signed approval record proves:

- A named approver reviewed the agent before it accessed ePHI
- The approval was time-bounded (typically to a single session or shift)
- The approval covered only the declared scope

The approver's key is separate from the issuer key, ensuring that a compromised issuer cannot retroactively forge approvals. See [Tutorial: HITL approval workflows](../tutorials/hitl-approvals.md) for implementation details.

---

## § 164.308(a)(1) — Security management process

> *Implement policies and procedures to prevent, detect, contain, and correct security violations.*

**What agent-manifest provides**

**Detection:** A verification failure (any non-`VALID` result) is a security signal. Aggregate verification failures by agent identity in your SIEM to detect unusual patterns.

**Containment:** Revoke the agent's manifest via the CRL endpoint. Propagation to all verifiers checking the endpoint is immediate (next poll cycle, typically <30s).

**Correction:** Re-issue the manifest under a new signing key after rotating the compromised key. The key rotation procedure is documented in the [Revocation and key rotation tutorial](../tutorials/revocation.md).

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
