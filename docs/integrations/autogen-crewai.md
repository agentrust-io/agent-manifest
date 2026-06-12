# AutoGen and CrewAI integration

This guide covers agent-manifest integration patterns for two multi-agent frameworks: Microsoft AutoGen and CrewAI. Both follow the same three-step pattern  -  issue, attach, verify  -  applied to each framework's agent model.

## Prerequisites

```bash
# AutoGen
pip install "agent-manifest[server]" pyautogen

# CrewAI
pip install "agent-manifest[server]" crewai
```

---

## AutoGen

AutoGen organises conversations between `AssistantAgent` and `UserProxyAgent` instances. Each agent has a role, a system message, and a code execution policy. Agent-manifest adds a cryptographic identity to each participant.

### Issue a manifest per AutoGen agent

```python
import hashlib
from datetime import datetime, timedelta, timezone

from agent_manifest import (
    Manifest, ArtifactBindings, ModelIdentityBinding, SystemPromptBinding,
    PolicyBundleBinding,
    CryptoProfile, DeploymentType, EnforcementMode,
    ModelAttestationType, PolicyLanguage,
    generate_ed25519,
)
from agent_manifest._types import ManifestId
from agent_manifest._signing import Ed25519Signer

def issue_manifest(agent_id: str, system_message: str, model: str) -> dict:
    kp = generate_ed25519()
    now = datetime.now(timezone.utc)
    m = Manifest(
        manifest_id=str(ManifestId.generate()),
        agent_id=agent_id,
        version="0.1",
        issued_at=now,
        expires_at=now + timedelta(hours=8),
        issuer="spiffe://trust.example/signing-authority",
        crypto_profile=CryptoProfile.standard,
        artifacts=ArtifactBindings(
            model_identity=ModelIdentityBinding(
                provider="openai",
                model_id=model,
                version="2024-08-06",
                deployment_type=DeploymentType.api,
                model_attestation_type=ModelAttestationType.provider_asserted,
                bound_at=now,
            ),
            system_prompt=SystemPromptBinding(
                hash="sha256:" + hashlib.sha256(system_message.encode()).hexdigest(),
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
        ),
    )
    signer = Ed25519Signer(kp)
    return signer.sign(m.model_dump(mode="json"))

PLANNER_SYSTEM = "You plan tasks and delegate to the executor. Never run code yourself."
EXECUTOR_SYSTEM = "You execute Python code produced by the planner. Refuse unsafe commands."

planner_manifest  = issue_manifest("spiffe://trust.example/autogen/planner",  PLANNER_SYSTEM,  "gpt-4o")
executor_manifest = issue_manifest("spiffe://trust.example/autogen/executor", EXECUTOR_SYSTEM, "gpt-4o-mini")

MANIFEST_STORE = {
    planner_manifest["manifest_id"]:  planner_manifest,
    executor_manifest["manifest_id"]: executor_manifest,
}
```

### Attach manifests to AutoGen agents

AutoGen agents carry state in their `_oai_messages` list and through a `system_message`. Inject the manifest ID into the system message so every response carries the agent's identity claim.

```python
import autogen

planner = autogen.AssistantAgent(
    name="planner",
    system_message=(
        f"{PLANNER_SYSTEM}\n\n"
        f"[agent-manifest-id: {planner_manifest['manifest_id']}]"
    ),
    llm_config={"model": "gpt-4o"},
)

executor = autogen.UserProxyAgent(
    name="executor",
    system_message=(
        f"{EXECUTOR_SYSTEM}\n\n"
        f"[agent-manifest-id: {executor_manifest['manifest_id']}]"
    ),
    human_input_mode="NEVER",
    code_execution_config={"work_dir": "coding", "use_docker": True},
)
```

### Verify manifests in a custom reply function

Override the default reply to check the sender's manifest before processing its message:

```python
from agent_manifest._verify import (
    OverallResult, RevocationStore, VerificationContext, verify_manifest,
)
import re

REVOCATION_STORE = RevocationStore()

def verified_reply(recipient, messages, sender, config):
    """Only accept messages from verified agents."""
    last_msg = messages[-1].get("content", "") if messages else ""
    match = re.search(r"\[agent-manifest-id: ([^\]]+)\]", last_msg)

    if match:
        manifest_id = match.group(1)
        manifest = MANIFEST_STORE.get(manifest_id)
        if manifest is None:
            return True, f"REJECTED: Unknown manifest {manifest_id}"
        result = verify_manifest(manifest, VerificationContext(), REVOCATION_STORE)
        if result.result != OverallResult.VALID:
            return True, f"REJECTED: Manifest {result.result}"

    return False, None   # fall through to default reply

executor.register_reply(autogen.AssistantAgent, verified_reply, position=0)
```

### Run the conversation

```python
executor.initiate_chat(
    planner,
    message="Write and run a Python script that fetches the top 5 trending GitHub repos today.",
)
```

---

## CrewAI

CrewAI organises work as `Crew` → `Agent` → `Task` → `Tool`. Each agent has a role, goal, and backstory. Agent-manifest adds cryptographic identity to each crew member.

### Issue a manifest per CrewAI agent

```python
def issue_crewai_manifest(role: str, goal: str, model: str) -> dict:
    agent_id = f"spiffe://trust.example/crew/{role.lower().replace(' ', '-')}"
    return issue_manifest(agent_id, f"Role: {role}. Goal: {goal}", model)

researcher_manifest = issue_crewai_manifest("Researcher", "Find accurate data from public sources", "gpt-4o")
writer_manifest     = issue_crewai_manifest("Writer",     "Produce clear summaries for executives",  "gpt-4o-mini")

MANIFEST_STORE.update({
    researcher_manifest["manifest_id"]: researcher_manifest,
    writer_manifest["manifest_id"]:     writer_manifest,
})
```

### Build the crew with manifests in agent metadata

CrewAI agents accept a `verbose` flag and custom kwargs. Store the manifest ID as an attribute on the agent object for use in tools and task callbacks.

```python
from crewai import Agent, Task, Crew, Process

class VerifiedAgent(Agent):
    """CrewAI Agent subclass that carries a manifest ID."""

    def __init__(self, manifest: dict, **kwargs):
        super().__init__(**kwargs)
        self.manifest_id = manifest["manifest_id"]

researcher = VerifiedAgent(
    manifest=researcher_manifest,
    role="Researcher",
    goal="Find accurate data from public sources",
    backstory="An expert at locating and validating primary sources.",
    verbose=True,
    allow_delegation=False,
)

writer = VerifiedAgent(
    manifest=writer_manifest,
    role="Writer",
    goal="Transform research into executive summaries",
    backstory="A concise technical writer with a finance background.",
    verbose=True,
    allow_delegation=False,
)
```

### Verify manifests in a task callback

Use a task callback to verify the agent's manifest before the task result is accepted:

```python
from crewai import Task
from agent_manifest._verify import (
    OverallResult, RevocationStore, VerificationContext, verify_manifest,
)

REVOCATION_STORE = RevocationStore()

def manifest_guard(output):
    """Callback run after each task  -  verifies the executing agent's manifest."""
    agent = output.agent   # the VerifiedAgent that produced this output
    if hasattr(agent, "manifest_id"):
        manifest = MANIFEST_STORE.get(agent.manifest_id)
        if manifest:
            result = verify_manifest(manifest, VerificationContext(), REVOCATION_STORE)
            if result.result != OverallResult.VALID:
                raise PermissionError(
                    f"Task output from unverified agent: {result.result}"
                )

research_task = Task(
    description="Research the current state of confidential computing adoption in financial services.",
    expected_output="A structured report with sources, key vendors, and adoption metrics.",
    agent=researcher,
    callback=manifest_guard,
)

writing_task = Task(
    description="Write a two-page executive summary of the research findings.",
    expected_output="A two-page executive summary in plain English.",
    agent=writer,
    context=[research_task],
    callback=manifest_guard,
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task, writing_task],
    process=Process.sequential,
    verbose=True,
)

result = crew.kickoff()
print(result)
```

---

## What's next

- [Tutorial: A2A delegation chains](../tutorials/delegation-chains.md)  -  cryptographic delegation between AutoGen agents
- [Tutorial: Revocation and key rotation](../tutorials/revocation.md)  -  revoke a crew member's manifest mid-operation
- [Integration: AGT](agt.md)  -  combine with AGT for policy-driven crew governance
