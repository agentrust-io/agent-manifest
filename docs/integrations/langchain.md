# LangChain integration

This guide shows how to attach an agent manifest to a LangChain agent and how to write a LangChain tool that verifies an incoming manifest before executing. No changes to LangChain internals are required.

## Prerequisites

```bash
pip install "agent-manifest[server]" langchain langchain-openai
```

---

## Part 1: Issue a manifest for a LangChain agent

Create the manifest once at startup  -  typically when the agent process initialises. The manifest captures what this agent is: its identity, the model it uses, its system prompt, and its tools.

```python
import hashlib
from datetime import datetime, timedelta, timezone

from agent_manifest import (
    Manifest, ArtifactBindings,
    ModelIdentityBinding, SystemPromptBinding, ToolManifestBinding,
    PolicyBundleBinding, ToolEntry,
    CryptoProfile, DeploymentType, EnforcementMode,
    ModelAttestationType, PolicyLanguage, RugPullPolicy,
    generate_ed25519,
)
from agent_manifest._types import ManifestId
from agent_manifest._signing import Ed25519Signer

SYSTEM_PROMPT = "You are a financial research assistant. You may search public data only."
SIGNING_KEY = generate_ed25519()   # load from secure storage in production

now = datetime.now(timezone.utc)

manifest = Manifest(
    manifest_id=str(ManifestId.generate()),
    agent_id="spiffe://trust.example/agent/financial-research/prod",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=8),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(
        model_identity=ModelIdentityBinding(
            provider="openai",
            model_id="gpt-4o",
            version="2024-08-06",
            deployment_type=DeploymentType.api,
            model_attestation_type=ModelAttestationType.provider_asserted,
            bound_at=now,
        ),
        system_prompt=SystemPromptBinding(
            hash="sha256:" + hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
            version="1.0.0",
            classification="internal",
            bound_at=now,
        ),
        policy_bundle=PolicyBundleBinding(
            hash="sha256:" + hashlib.sha256(b"policy-bundle-v1").hexdigest(),
            policy_language=PolicyLanguage.cedar,
            version="1.0.0",
            enforcement_mode=EnforcementMode.enforce,
            bound_at=now,
        ),
        tool_manifest=ToolManifestBinding(
            catalog_hash="sha256:" + hashlib.sha256(b"[search_public_data]").hexdigest(),
            tools=[
                ToolEntry(
                    tool_id="example.trust.search_public_data",
                    tool_name="search_public_data",
                    endpoint_id="spiffe://trust.example/mcp/research-tools/prod",
                    schema_hash="sha256:" + hashlib.sha256(b"schema").hexdigest(),
                    description_hash="sha256:" + hashlib.sha256(b"description").hexdigest(),
                    version="1.0.0",
                ),
            ],
            rug_pull_policy=RugPullPolicy.require_reapproval,
            bound_at=now,
        ),
    ),
)

signer = Ed25519Signer(SIGNING_KEY)
SIGNED_MANIFEST = signer.sign(manifest.model_dump(mode="json"))
MANIFEST_ID = SIGNED_MANIFEST["manifest_id"]
```

---

## Part 2: Attach the manifest to outbound requests

LangChain agents make tool calls and HTTP requests. Pass the `manifest_id` in a header so the downstream service can verify who is calling.

### Option A: Custom callback handler

Use a `BaseCallbackHandler` to inject the manifest ID into every LLM call's metadata:

```python
from langchain_core.callbacks import BaseCallbackHandler
from langchain_openai import ChatOpenAI
from langchain.agents import AgentExecutor, create_openai_tools_agent
from langchain_core.prompts import ChatPromptTemplate

class ManifestCallbackHandler(BaseCallbackHandler):
    def __init__(self, manifest_id: str) -> None:
        self.manifest_id = manifest_id

    def on_llm_start(self, serialized, prompts, **kwargs):
        # Attach to run metadata  -  available in traces and logs
        kwargs.setdefault("metadata", {})["agent_manifest_id"] = self.manifest_id

MANIFEST_HEADER = {"x-agent-manifest-id": MANIFEST_ID}

llm = ChatOpenAI(
    model="gpt-4o-2024-08-06",
    default_headers=MANIFEST_HEADER,   # passed on every OpenAI API call
)

prompt = ChatPromptTemplate.from_messages([
    ("system", SYSTEM_PROMPT),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])
```

### Option B: Header injection in a custom tool

For tools that call internal services, pass the manifest ID in the tool's HTTP client:

```python
import httpx
from langchain_core.tools import tool

@tool
def search_internal_database(query: str) -> str:
    """Search the internal research database."""
    response = httpx.get(
        "https://research-db.internal/search",
        params={"q": query},
        headers={"x-agent-manifest-id": MANIFEST_ID},
    )
    return response.text
```

---

## Part 3: Verify an incoming manifest inside a LangChain tool

Write a tool that refuses to execute unless the caller provides a valid manifest. This is the **relying-party pattern**: a tool that only accepts requests from verified agents.

```python
import json
from langchain_core.tools import tool
from agent_manifest._verify import (
    OverallResult, RevocationStore, VerificationContext, verify_manifest,
)

# Load at startup  -  shared across all tool invocations
MANIFEST_STORE: dict[str, dict] = {}
REVOCATION_STORE = RevocationStore()

def load_manifest(manifest_id: str) -> dict | None:
    """Load a manifest from your store (database, file, cache)."""
    return MANIFEST_STORE.get(manifest_id)

@tool
def execute_trade(
    ticker: str,
    quantity: int,
    caller_manifest_id: str,
) -> str:
    """Execute a trade. Requires a valid caller manifest with trading scope."""
    manifest = load_manifest(caller_manifest_id)
    if manifest is None:
        return "ERROR: Unknown manifest  -  request rejected"

    ctx = VerificationContext(enforce_hitl=True)
    result = verify_manifest(manifest, ctx, REVOCATION_STORE)

    if result.result != OverallResult.VALID:
        return f"ERROR: Manifest verification failed  -  {result.result}"

    # Proceed only if verification passed
    return f"Trade executed: {quantity}x {ticker}"
```

---

## Part 4: Complete example

```python
from langchain.agents import AgentExecutor, create_openai_tools_agent

tools = [search_internal_database, execute_trade]

agent = create_openai_tools_agent(llm, tools, prompt)
executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[ManifestCallbackHandler(MANIFEST_ID)],
    verbose=True,
)

result = executor.invoke({"input": "What is the current P/E ratio of AAPL?"})
print(result["output"])
```

---

## What to store in the manifest store

When a LangChain agent presents its `manifest_id`, your service needs to look it up. Options:

| Store | When to use |
|-------|-------------|
| In-memory dict | Development, single-process deployments |
| Redis | Multi-process / multi-host; TTL matches `expires_at` |
| PostgreSQL | Long-term audit history; query by `agent_id`, `issuer`, time range |
| `.well-known` endpoint | Agents publish their own manifest; verifier fetches on demand |

---

## What's next

- [Tutorial: Server-side verification](../tutorials/server-side-verification.md)  -  full verification router for a FastAPI service
- [Tutorial: Revocation and key rotation](../tutorials/revocation.md)  -  revoke a LangChain agent's manifest on compromise
