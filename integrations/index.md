# Integrations

Agent-manifest is framework-agnostic - it is a signing and verification layer, not an agent runtime. These guides show how to attach it to the most common Python agent frameworks.

| Integration                                                                                        | What it covers                                                                                                           |
| -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| [LangChain](https://manifest.agentrust-io.com/integrations/langchain/index.md)                     | Manifest for a LangChain agent; tool wrapper that verifies caller manifests                                              |
| [OpenAI Agents SDK](https://manifest.agentrust-io.com/integrations/openai-agents/index.md)         | Manifest per agent; manifest handoff verification during agent handoffs                                                  |
| [AutoGen and CrewAI](https://manifest.agentrust-io.com/integrations/autogen-crewai/index.md)       | Per-agent manifests in AutoGen conversations and CrewAI crews                                                            |
| [AGT (Agent Governance Toolkit)](https://manifest.agentrust-io.com/integrations/agt/index.md)      | Using agent-manifest as the identity layer feeding AGT policy and trust scores                                           |
| [NVIDIA OpenShell](https://manifest.agentrust-io.com/integrations/openshell/index.md)              | Binding the approved OpenShell, ACS, workload, and tool configuration to runtime TRACE evidence                          |
| [Agent Credentials](https://manifest.agentrust-io.com/integrations/agent-credentials/index.md)     | Joining a credential decision to the exact manifest and signed runtime evidence                                          |
| [Standards landscape](https://manifest.agentrust-io.com/integrations/standards-landscape/index.md) | How Agent Manifest connects to Agent Card, registration, credentials, BOM, provenance, attestation, and runtime evidence |

## Common pattern

Issue a manifest, attach its identifier or complete signed envelope, and verify it before allowing the protected operation. An identifier in a header, callback, or trace is correlation metadata; the recipient still needs the actual signed object, independently approved keys and runtime inputs, and current revocation state.

## Run a local verification gate

Complete the [first-manifest example](https://manifest.agentrust-io.com/getting-started/index.md), append this block to `first_manifest.py`, and run it again. It tests a framework-independent boundary with synthetic inputs; it does not call a model or install a framework adapter.

```
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

Obtain `approved_context` and revocation state through the recipient's own configuration and evidence collection. Never let a caller submit its own expected hashes or trusted-key map as authorization. A `VALID` result applies to the declared bindings and supplied checks; the application separately authorizes the requested operation and delegation scope.

Place this gate before tool, handoff, or service side effects. Recheck when the relevant state changes; attaching a manifest once at startup does not enforce later drift, revocation, or caller permissions. The framework pages identify where to connect this boundary and link to current framework APIs.
