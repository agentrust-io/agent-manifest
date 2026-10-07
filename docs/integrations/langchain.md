# LangChain Integration

This page shows LangChain users where to check a calling agent's manifest before a protected tool runs. You get a tool call that only goes ahead when the caller's signed record matches what you approved. Start with the [runnable verification gate](index.md#run-a-local-verification-gate); it shows both an accepted and a rejected case and needs no model account.

## Connect the gate

Build the manifest from the approved agent setup, as in the [first-manifest example](../getting-started.md). Store the full signed record somewhere the receiving side can trust, and give the receiving side the matching public key in its own settings. Putting a manifest ID into LangChain callback data does not prove who the caller is, and it does not become an HTTP header by itself.

In current LangChain agents, use the documented [middleware extension points](https://docs.langchain.com/oss/python/langchain/middleware/overview) (hooks that run around each step) to catch a tool call before it runs. Or call the gate inside the service that owns the protected action. Check before the tool code runs, and pass any rejection back up so nothing happens.

Prompts, chosen tools and model settings can change while the agent runs, so they may not match what you saw at startup. Give the gate the values actually in use for this call. Keep LangChain's own tracing data for debugging; it must not stand in for the signature and artifact checks.

## Verify your wiring

Try five cases: an accepted manifest, an unknown signer, changed runtime inputs, a revoked ID, and an artifact the gate cannot fetch. Confirm that every rejected case stops before the protected tool, including on retries and other code paths that reach the same tool. Repeat with the exact LangChain version you plan to deploy.

This page shows where to connect the check. Agent Manifest does not install middleware for you or check every LangChain call automatically.
