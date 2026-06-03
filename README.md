# Agent Manifest SDK

One function call hardware-anchors all 10 artifacts defining an agent at deployment. Provider auto-selects based on available hardware — zero infrastructure change for most developers.

```python
pip install agent-manifest
```

```python
from agent_manifest import AgentManifest, attest

manifest = AgentManifest(
    model_id="claude-sonnet-4-6",
    system_prompt="./prompts/system_v3.txt",
    policy_bundle="./policies/",
    tool_schemas="./tools/",
    rag_corpus_hash="sha256:f2a8d1...",
    memory_baseline="./memory/approved.json",
    approved_by="compliance@example.com",
)
attestation = attest(manifest, provider="auto")
# auto: tpm -> sev-snp -> tdx -> opaque (based on available hardware)
```

## The 10 Attested Artifacts

| # | Artifact | Why It Matters |
|---|----------|---------------|
| 1 | System Prompt | Tampered prompt = different agent persona and safety boundaries |
| 2 | Policy Bundle | Swapped policy = unapproved permissions |
| 3 | Tool Schemas | Schema swap expands agent capabilities beyond approval |
| 4 | Model Identity | Unapproved model version may lack safety alignment |
| 5 | RAG Corpus | Knowledge base poisoning changes outputs without touching policy |
| 6 | Memory Baseline | Corruption in long-running agents undetectable today |
| 7 | Decision Trace | Hardware-signed reasoning record for litigation defense |
| 8 | A2A Delegation | Multi-agent trust chains must be attested to prevent spoofing |
| 9 | Supply Chain | Container + SLSA provenance, CoSAI WS1 aligned |
| 10 | HITL Approvals | Human oversight records required by EU AI Act Art. 14 |

## Hardware Providers

| Provider | Where It Runs | Assurance Level |
|----------|--------------|----------------|
| `tpm` | Any VM with Trusted Launch | Medium — zero infrastructure change |
| `sev-snp` | Azure DCasv5, AWS C6a Nitro | High |
| `tdx` | Azure DCedsv5, GCP C3 | High |
| `opaque` | Opaque Managed Runtime | Highest |

## Standards

The Agent Manifest Specification is being submitted to [CoSAI](https://responsible-ai.foundation) under OASIS Open, building on CoSAI WS4 published work (Secure-by-Design Principles, MCP Security Taxonomy, Agentic IAM Framework). Submission target: September 2026.

## Status

Private. Developer preview at Ai4 Las Vegas, August 4, 2026.

## License

Apache 2.0