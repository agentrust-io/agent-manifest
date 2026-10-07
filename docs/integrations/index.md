# Integrations

An Agent Manifest is a signed record of what an agent was approved to run. These guides show where to add a manifest check to the agent software you already use. They are for developers who run agents built with LangChain, the OpenAI Agents SDK, AutoGen, CrewAI or similar tools. Each guide shows the point in that framework where you check the agent's signed record before it is allowed to do something that matters.

Agent Manifest works with any framework. It signs and checks records about an agent; it does not run the agent. A framework is the library your agent is built on.

| Integration | What it covers |
|-------------|---------------|
| [LangChain](langchain.md) | Manifest for a LangChain agent; tool wrapper that verifies caller manifests |
| [OpenAI Agents SDK](openai-agents.md) | Manifest per agent; manifest handoff verification during agent handoffs |
| [AutoGen and CrewAI](autogen-crewai.md) | Per-agent manifests in AutoGen conversations and CrewAI crews |
| [AGT (Agent Governance Toolkit)](agt.md) | Passing a checked manifest into AGT, which decides what an agent may do |
| [NVIDIA OpenShell](openshell.md) | Linking the approved OpenShell sandbox setup to TRACE records of what ran |
| [Agent Credentials](agent-credentials.md) | Tying a credential check to the exact manifest and to signed records of what ran |
| [Standards landscape](standards-landscape.md) | How Agent Manifest fits next to Agent Cards, credentials, software inventories, build records, hardware reports and runtime records |

## Common pattern

The pattern is the same everywhere. Create a manifest, send its ID or the full signed record along with the agent, and check it before the agent is allowed to do the protected thing (call a tool, hand work to another agent, reach a service).

An ID in a header, callback or log only helps you find and match records. To check anything, the receiving side still needs the full signed record, its own list of trusted keys, its own copy of the values it expects to see at runtime, and an up-to-date list of revoked (withdrawn) manifests.

## Run a local verification gate

This is a small check, called a gate, that refuses to continue unless the manifest verifies. Complete the [first-manifest example](../getting-started.md), add this block to the end of `first_manifest.py`, and run it again. It uses made-up inputs and works without any framework: it does not call a model or install anything extra.

```python
from agent_manifest import OverallResult

def require_manifest(received, approved_context, revocations):
    result = verify_manifest(received, approved_context, revocations)
    if result.result != OverallResult.VALID:
        raise PermissionError(f"Manifest rejected: {result.result.value}")
    return result

require_manifest(record, context, RevocationStore())
print("PASS: approved manifest accepted by the gate")
for rejected_context in (
    context.model_copy(update={"trusted_keys": {}}),
    context.model_copy(update={"system_prompt_hash": "sha256:" + "0" * 64}),
):
    try:
        require_manifest(record, rejected_context, RevocationStore())
    except PermissionError:
        pass
    else:
        raise RuntimeError("Gate accepted missing trust or changed runtime input")
print("PASS: missing trust and changed runtime input blocked")
```

The receiving side must load `approved_context` (the values it expects and the keys it trusts) and the revocation list from its own configuration. Never let the caller supply its own expected hashes or trusted keys: that would let it approve itself. A `VALID` result covers only the bindings in the manifest and the checks you supplied. Your application still decides separately whether the requested action and any handing-on of authority are allowed.

Put the gate before anything with a real effect: a tool call, a handoff or a service request. Check again when something relevant changes. Attaching a manifest once at startup does not catch later changes, revocations or permission changes. The framework pages below show where to connect the gate and link to each framework's current documentation.
