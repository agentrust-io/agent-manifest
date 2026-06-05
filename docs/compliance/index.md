# Compliance

Agent-manifest satisfies traceability, accountability, and audit requirements across multiple regulatory frameworks. These one-pagers map specific obligations to agent-manifest capabilities and are written for compliance officers and auditors.

| Framework | Jurisdiction | Primary obligation addressed |
|-----------|-------------|------------------------------|
| [EU AI Act](eu-ai-act.md) | European Union | Risk management, transparency, human oversight for high-risk AI |
| [DORA](dora.md) | European Union (financial services) | ICT risk management, incident reporting, operational resilience |
| [GDPR](gdpr.md) | European Union | Accountability, data protection by design, records of processing |
| [HIPAA](hipaa.md) | United States (healthcare) | Access control, audit controls, integrity, human oversight |

## What agent-manifest provides

Every signed manifest is a tamper-evident record that answers five questions regulators ask about AI systems:

1. **Who is this agent?** — SPIFFE URI identity, signed by an issuer key
2. **What is it running?** — Model, system prompt, and tool hashes cryptographically bound
3. **How was it deployed?** — Attestation level (0–3), optional hardware enclave evidence
4. **Who authorised it?** — Delegation chain with issuer signature at each hop
5. **Has a human reviewed it?** — HITL approval record signed by a named approver

These five properties map directly to the accountability, transparency, and human oversight requirements in every framework listed above.
