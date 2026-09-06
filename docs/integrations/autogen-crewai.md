# AutoGen and CrewAI Integration

Use a manifest gate before starting an agent task and before sensitive tool operations. The [local integration example](index.md#run-a-local-verification-gate) tests that gate with approved inputs and rejection cases.

## AutoGen

Place the gate in the application wrapper that invokes the agent or team and in the service handling protected tools. Carry a manifest identifier for correlation, but resolve and verify the complete signed object using recipient-owned trust and runtime inputs.

Use the [current AgentChat guide](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/index.html) for your selected package and invocation APIs. Examples written for older `pyautogen` conversation classes are not interchangeable with current AgentChat. Pin and test the version you deploy.

## CrewAI

CrewAI provides a `before_kickoff` hook for application work before a crew begins. Perform the manifest check there before returning inputs. See [CrewAI kickoff hooks](https://docs.crewai.com/en/learn/before-and-after-kickoff-hooks) for the supported API.

A kickoff check establishes state only at that point. Gate sensitive tools at execution time as well when revocation, runtime inputs, or authorization can change during the run. Propagate failures instead of catching them and continuing the crew.

## Shared requirements

Retain issuer and revocation authority keys independently of incoming manifests. Use complete signed objects: the v0.1 `Ed25519Signer.sign()` API returns a signature block that must be attached to the manifest, while v0.2 uses COSE bytes.

Test that an unknown signer, revoked ID, or mismatched runtime input prevents protected work. Manifest verification and task authorization remain separate checks; neither framework applies them automatically by attaching metadata.
