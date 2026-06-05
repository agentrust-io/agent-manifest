# Integrations

Agent-manifest is framework-agnostic — it is a signing and verification layer, not an agent runtime. These guides show how to attach it to the most common Python agent frameworks.

| Integration | What it covers |
|-------------|---------------|
| [LangChain](langchain.md) | Manifest for a LangChain agent; tool wrapper that verifies caller manifests |
| [OpenAI Agents SDK](openai-agents.md) | Manifest per agent; manifest handoff verification during agent handoffs |
| [AutoGen and CrewAI](autogen-crewai.md) | Per-agent manifests in AutoGen conversations and CrewAI crews |
| [AGT (Agent Governance Toolkit)](agt.md) | Using agent-manifest as the identity layer feeding AGT policy and trust scores |

## Common pattern

Every integration follows the same three steps:

1. **Issue** — create and sign a manifest that identifies the agent and binds its artifacts
2. **Attach** — pass the `manifest_id` to the relying party (header, metadata, context field)
3. **Verify** — the relying party calls `verify_manifest()` before acting on the agent's output

The framework-specific pages show where exactly to hook each step.
