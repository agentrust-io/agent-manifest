# OpenAI Agents SDK Integration

This page is for developers using the OpenAI Agents SDK. It shows where to check an agent's manifest before one agent hands work to another (a handoff) or before a protected tool runs. Start with the [runnable verification gate](index.md#run-a-local-verification-gate); it uses made-up inputs and needs no model API key.

## Connect a handoff

Keep the signed manifest, the values you expect (the verification context) and the list of revoked manifests in data your application controls. If the model writes out a manifest ID, treat it only as a pointer for looking the record up. It must never choose which keys you trust or which runtime hashes you expect.

The Agents SDK provides `handoff(..., on_handoff=...)`. Run the checks at the start of `on_handoff`, before your application does anything with a real effect, and raise an error to reject: if the callback returns normally, the handoff goes ahead. `is_enabled` can turn a handoff on or off, but it runs before the handoff arguments exist, so it cannot check them. See the SDK's [handoff documentation](https://openai.github.io/openai-agents-python/handoffs/).

Check the signed record against the issuer keys you approved and the values actually in use at runtime. Handing work to another agent also needs your application's own checks on delegation (passing authority on) and scope (how much authority). A valid manifest does not, on its own, approve the handoff or the data passed with it.

## Test the boundary

Before running a live model, test four cases: accepted, unknown key, revoked, and changed artifact. Confirm each rejection stops the receiving agent and any tools after it. Test direct tool calls separately; a handoff hook does not guard every path to a tool.

Pin the Agents SDK version your application uses and confirm how its hooks behave in that version. This page gives the checking pattern; the framework does not run Agent Manifest checks for you.
