# Compliance

Agent Manifest supplies signed configuration and provenance evidence that can support a compliance review. These pages map capabilities to topics in several regulatory frameworks. A valid manifest does not by itself establish regulatory compliance; that assessment depends on the deployed system, its controls, and the applicable obligations.

| Framework                                                                    | Jurisdiction                        | Primary obligation addressed                                     |
| ---------------------------------------------------------------------------- | ----------------------------------- | ---------------------------------------------------------------- |
| [EU AI Act](https://manifest.agentrust-io.com/compliance/eu-ai-act/index.md) | European Union                      | Risk management, transparency, human oversight for high-risk AI  |
| [DORA](https://manifest.agentrust-io.com/compliance/dora/index.md)           | European Union (financial services) | ICT risk management, incident reporting, operational resilience  |
| [GDPR](https://manifest.agentrust-io.com/compliance/gdpr/index.md)           | European Union                      | Accountability, data protection by design, records of processing |
| [HIPAA](https://manifest.agentrust-io.com/compliance/hipaa/index.md)         | United States (healthcare)          | Access control, audit controls, integrity, human oversight       |

## What agent-manifest provides

The evidence available depends on which bindings and optional records the producer includes and which checks the recipient performs:

| Evidence                                           | What to check                                                                            |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Agent and issuer identity                          | Signature against an independently trusted issuer and the expected agent identity        |
| Declared prompt, policy, tools, and model bindings | Compare with independently supplied deployment inputs; omitted bindings are not verified |
| Hardware evidence, when supplied                   | Provider-specific appraisal, expected measurements, key binding, and deployment limits   |
| Delegation, when supplied                          | Trusted authority, signatures, continuity, and scope restrictions                        |
| Human approval, when supplied                      | Approver authority, signature, scope, and freshness                                      |

Start with [your first manifest](https://manifest.agentrust-io.com/getting-started/index.md) to see the checks in a local example. Read [limitations](https://manifest.agentrust-io.com/limitations/index.md) before treating a signed declaration as evidence of runtime behavior.
