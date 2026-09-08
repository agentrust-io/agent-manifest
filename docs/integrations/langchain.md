# LangChain Integration

Verify a caller's manifest before a protected tool executes. Begin with the [runnable verification gate](index.md#run-a-local-verification-gate); it demonstrates both acceptance and rejection without model credentials.

## Connect the gate

Build the manifest from the approved agent configuration using the [first-manifest example](../getting-started.md). Keep the complete signed object in an authenticated manifest store and its public key in the recipient's trust configuration. A manifest ID attached to callback metadata does not itself authenticate the caller or automatically become an HTTP header.

For current LangChain agents, use the documented [middleware extension points](https://docs.langchain.com/oss/python/langchain/middleware/overview) to intercept tool execution, or call the gate inside the service that owns the protected operation. Verify before invoking the tool handler, and propagate rejection so no side effect occurs.

Dynamic prompts, selected tools, and model settings can differ from startup configuration. Supply the actual approved runtime observations for the operation. Capture framework metadata separately for tracing; it must not substitute for signature and artifact checks.

## Verify your wiring

Exercise an accepted manifest, an unknown issuer, changed runtime inputs, a revoked ID, and an unavailable artifact. Confirm rejected cases never reach the protected tool, including retries and alternate execution paths. Repeat with your pinned LangChain version before deploying.

This page describes application integration points. Agent Manifest does not automatically install middleware or gate every LangChain call.
