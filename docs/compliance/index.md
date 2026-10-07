# Compliance

These pages are for compliance officers, auditors and the engineers who support them. Each one takes a law or regulation and shows which of its requirements an Agent Manifest can help you produce evidence for, and which it cannot.

An Agent Manifest is a signed record of how an AI agent was set up and who approved it. That record can support a compliance review. A valid manifest does not, on its own, make a system compliant: that depends on the whole deployed system, its other controls, and the rules that apply to you.

| Framework | Jurisdiction | Primary obligation addressed |
|-----------|-------------|------------------------------|
| [EU AI Act](eu-ai-act.md) | European Union | Risk management, transparency, human oversight for high-risk AI |
| [DORA](dora.md) | European Union (financial services) | ICT risk management, incident reporting, operational resilience |
| [GDPR](gdpr.md) | European Union | Accountability, data protection by design, records of processing |
| [HIPAA](hipaa.md) | United States (healthcare) | Access control, audit controls, integrity, human oversight |

## What agent-manifest provides

What you can show depends on which parts the issuer put in the manifest and which checks the reviewer actually runs:

| Evidence | What to check |
|---|---|
| Agent and issuer identity | Signature against an independently trusted issuer and the expected agent identity |
| Declared prompt, policy, tools, and model bindings | Compare with independently supplied deployment inputs; omitted bindings are not verified |
| Hardware evidence, when supplied | Provider-specific appraisal, expected measurements, key binding, and deployment limits |
| Delegation, when supplied | Trusted authority, signatures, continuity, and scope restrictions |
| Human approval, when supplied | Approver authority, signature, scope, and freshness |

Start with [your first manifest](../getting-started.md) to see the checks in a local example. Read [limitations](../limitations.md) before treating a signed statement about setup as evidence of what the agent did while running.
