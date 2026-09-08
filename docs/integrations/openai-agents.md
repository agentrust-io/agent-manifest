# OpenAI Agents SDK Integration

Verify a manifest before an agent handoff or protected tool operation. Start with the [runnable verification gate](index.md#run-a-local-verification-gate); it uses synthetic inputs and needs no model API key.

## Connect a handoff

Keep the signed manifest, approved verification context, and revocation state in application-owned context. A model-generated manifest ID is only a locator and must not choose the recipient's trust anchors or expected runtime hashes.

The Agents SDK exposes `handoff(..., on_handoff=...)`. Perform checks at the start of `on_handoff`, before application side effects, and raise on rejection: a successful callback return allows the transfer to continue. `is_enabled` can control availability but cannot authorize handoff arguments that have not yet been generated. See the SDK's [handoff documentation](https://openai.github.io/openai-agents-python/handoffs/).

Authenticate the signed object against approved issuer keys and current runtime observations. A handoff to another agent also needs the application's delegation and scope checks. A valid manifest does not independently authorize the requested transfer or input data.

## Test the boundary

Test accepted, unknown-key, revoked, and changed-artifact cases before running a live model. Confirm each rejection prevents the receiving agent and downstream tools from executing. Cover direct tool calls separately; a handoff hook is not a gate for every tool path.

Pin the Agents SDK version used by your application and verify its hook behavior. This page supplies the verification pattern; the framework does not automatically apply Agent Manifest checks.
