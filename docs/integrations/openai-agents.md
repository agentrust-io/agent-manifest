# OpenAI Agents SDK integration

This guide shows how to attach an agent manifest to an OpenAI Agents SDK agent and how to verify manifests during agent handoffs  -  the point where one agent delegates to another.

## Prerequisites

```bash
pip install "agent-manifest[server]" openai-agents
```

---

## Part 1: Issue a manifest for an OpenAI agent

Create the manifest at agent startup. The `agent_id` should identify this specific agent role, not the OpenAI organization.

```python
import hashlib
from datetime import datetime, timedelta, timezone

from agent_manifest import (
    Manifest, ArtifactBindings,
    ModelIdentityBinding, SystemPromptBinding, ToolManifestBinding,
    ToolEntry, CryptoProfile,
    generate_ed25519,
)
from agent_manifest._types import ManifestId
from agent_manifest._signing import Ed25519Signer

ORCHESTRATOR_PROMPT = (
    "You are an orchestrator agent. Delegate data retrieval to the fetcher agent "
    "and analysis to the analyst agent. Never access external systems directly."
)

SIGNING_KEY = generate_ed25519()
now = datetime.now(timezone.utc)

orchestrator_manifest = Manifest(
    manifest_id=str(ManifestId.generate()),
    agent_id="spiffe://trust.example/agent/orchestrator/prod",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=8),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(
        model_identity=ModelIdentityBinding(
            provider="openai",
            model_family="gpt-4o",
            version="gpt-4o-2024-08-06",
        ),
        system_prompt=SystemPromptBinding(
            hash="sha256:" + hashlib.sha256(ORCHESTRATOR_PROMPT.encode()).hexdigest(),
        ),
        tool_manifest=ToolManifestBinding(
            catalog_hash="sha256:" + hashlib.sha256(b"[handoff_to_fetcher,handoff_to_analyst]").hexdigest(),
            tools=[
                ToolEntry(name="handoff_to_fetcher", version="1.0.0"),
                ToolEntry(name="handoff_to_analyst", version="1.0.0"),
            ],
        ),
    ),
)

signer = Ed25519Signer(SIGNING_KEY)
ORCHESTRATOR_SIGNED = signer.sign(orchestrator_manifest.model_dump(mode="json"))
ORCHESTRATOR_MANIFEST_ID = ORCHESTRATOR_SIGNED["manifest_id"]
```

---

## Part 2: Thread the manifest ID through the context

OpenAI Agents SDK uses a `RunContext` (or equivalent context dict) to pass state through a run. Thread the manifest ID as a context variable so every tool and handoff can access it.

```python
from dataclasses import dataclass
from agents import Agent, Runner, RunContext, function_tool, handoff

@dataclass
class ManifestContext:
    orchestrator_manifest_id: str
    caller_manifest_id: str | None = None   # set by sub-agents

# ── Orchestrator ────────────────────────────────────────────────────────────

FETCHER_PROMPT = "You retrieve data from authorised public sources only."
ANALYST_PROMPT  = "You analyse structured data and produce summaries."

fetcher_agent = Agent(
    name="fetcher",
    instructions=FETCHER_PROMPT,
    model="gpt-4o-mini",
)

analyst_agent = Agent(
    name="analyst",
    instructions=ANALYST_PROMPT,
    model="gpt-4o-mini",
)

orchestrator_agent = Agent(
    name="orchestrator",
    instructions=ORCHESTRATOR_PROMPT,
    model="gpt-4o",
    handoffs=[fetcher_agent, analyst_agent],
)
```

---

## Part 3: Verify the manifest on handoff

Wrap each sub-agent with a handoff hook that checks the orchestrator's manifest before allowing the delegation. This is the **delegation verification pattern**.

```python
import json
from agents import handoff, RunContext
from agent_manifest._verify import (
    OverallResult, RevocationStore, VerificationContext, verify_manifest,
)

MANIFEST_STORE: dict[str, dict] = {
    ORCHESTRATOR_MANIFEST_ID: ORCHESTRATOR_SIGNED,
    # add sub-agent manifests here
}
REVOCATION_STORE = RevocationStore()

def verify_caller_manifest(manifest_id: str) -> None:
    """Raise if the caller's manifest is not VALID."""
    manifest = MANIFEST_STORE.get(manifest_id)
    if manifest is None:
        raise PermissionError(f"Unknown manifest: {manifest_id}")
    result = verify_manifest(manifest, VerificationContext(), REVOCATION_STORE)
    if result.result != OverallResult.VALID:
        raise PermissionError(f"Caller manifest {result.result}: {manifest_id}")

@function_tool
def handoff_to_fetcher(
    context: RunContext[ManifestContext],
    query: str,
) -> str:
    """Delegate a data-fetching task to the fetcher agent."""
    verify_caller_manifest(context.context.orchestrator_manifest_id)
    # Proceed with handoff after verification
    return f"Fetching: {query}"

@function_tool
def handoff_to_analyst(
    context: RunContext[ManifestContext],
    data: str,
) -> str:
    """Delegate an analysis task to the analyst agent."""
    verify_caller_manifest(context.context.orchestrator_manifest_id)
    return f"Analysing: {data}"
```

---

## Part 4: Run the pipeline with manifest context

```python
import asyncio

async def main():
    ctx = ManifestContext(orchestrator_manifest_id=ORCHESTRATOR_MANIFEST_ID)

    result = await Runner.run(
        orchestrator_agent,
        input="Fetch the latest AAPL earnings and summarise the key metrics.",
        context=ctx,
    )
    print(result.final_output)

asyncio.run(main())
```

---

## Part 5: Delegation chain for multi-hop handoffs

When the orchestrator delegates to the fetcher and the fetcher further delegates to a data-source agent, use a delegation chain (see [Tutorial: A2A delegation chains](../tutorials/delegation-chains.md)) to cryptographically bind the full delegation path.

```python
from agent_manifest._delegation import DelegationHopSigner

# The orchestrator signs hop 0, granting the fetcher read-only scope
orchestrator_kp = SIGNING_KEY
fetcher_manifest_id = str(ManifestId.generate())

hop_signer = DelegationHopSigner(keypair=orchestrator_kp)
hop0_sig = hop_signer.sign_hop(
    hop=0,
    principal_id="spiffe://trust.example/agent/orchestrator/prod",
    principal_type="agent",
    delegated_at=now.isoformat(),
    scope_grant={
        "tools": ["fetch_public_data"],
        "data_classifications": ["public"],
        "max_delegation_depth": 1,
        "approval_required": False,
    },
    manifest_id=fetcher_manifest_id,
)
# Attach hop0_sig to the fetcher's manifest delegation_chain field
```

---

## What's next

- [Tutorial: A2A delegation chains](../tutorials/delegation-chains.md)  -  full delegation chain implementation
- [Integration: AGT](agt.md)  -  use AGT policy to gate which orchestrators may hand off to which sub-agents
