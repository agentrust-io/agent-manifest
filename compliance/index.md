# Compliance

Agent-manifest satisfies traceability, accountability, and audit requirements across multiple regulatory frameworks. These one-pagers map specific obligations to agent-manifest capabilities and are written for compliance officers and auditors.

| Framework                                                                    | Jurisdiction                        | Primary obligation addressed                                     |
| ---------------------------------------------------------------------------- | ----------------------------------- | ---------------------------------------------------------------- |
| [EU AI Act](https://manifest.agentrust-io.com/compliance/eu-ai-act/index.md) | European Union                      | Risk management, transparency, human oversight for high-risk AI  |
| [DORA](https://manifest.agentrust-io.com/compliance/dora/index.md)           | European Union (financial services) | ICT risk management, incident reporting, operational resilience  |
| [GDPR](https://manifest.agentrust-io.com/compliance/gdpr/index.md)           | European Union                      | Accountability, data protection by design, records of processing |
| [HIPAA](https://manifest.agentrust-io.com/compliance/hipaa/index.md)         | United States (healthcare)          | Access control, audit controls, integrity, human oversight       |

## What agent-manifest provides

Every signed manifest is a tamper-evident record that answers five questions regulators ask about AI systems:

1. **Who is this agent?** - SPIFFE URI identity, signed by an issuer key
1. **What is it running?** - Model, system prompt, and tool hashes cryptographically bound
1. **How was it deployed?** - Attestation level (0–3), optional hardware enclave evidence
1. **Who authorised it?** - Delegation chain with issuer signature at each hop
1. **Has a human reviewed it?** - HITL approval record signed by a named approver

These five properties map directly to the accountability, transparency, and human oversight requirements in every framework listed above.
