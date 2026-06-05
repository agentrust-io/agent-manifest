# Multi-artifact manifest example

This example shows a manifest with four artifact bindings: model identity, system prompt, tool catalog, and RAG corpus. All four artifact hashes are cryptographically bound to the manifest.

## Files

| File | Description |
|------|-------------|
| `manifest.json` | Manifest with four artifact bindings |
| `artifacts/system-prompt.txt` | System prompt (SHA-256 matches `artifacts.system_prompt.hash`) |
| `artifacts/tool-catalog.json` | Tool catalog (SHA-256 matches `artifacts.tool_manifest.catalog_hash`) |
| `artifacts/rag-corpus-root.txt` | Merkle root of the RAG corpus (matches `artifacts.rag_corpus.merkle_root`) |
| `verify.sh` | Demonstrates integrity check passing and tamper detection |

## What each artifact binding covers

| Binding | Hash field | What it protects |
|---------|-----------|------------------|
| `model_identity` | `model_id` + `version` (not a hash) | Which model the agent is bound to |
| `system_prompt` | `hash` | Exact prompt bytes — any edit produces a different hash |
| `tool_manifest` | `catalog_hash` | The set of tools the agent can invoke |
| `rag_corpus` | `merkle_root` | The retrieval corpus — changing any document invalidates the root |

## Tamper detection

The verify script demonstrates what happens when `system-prompt.txt` is modified after the manifest is issued. The SHA-256 of the modified file no longer matches the hash in the manifest, producing a `MISMATCH` result.

This is the core guarantee: if any artifact changes after issuance, the verifier detects it without access to the original artifact — only the hash in the signed manifest is needed.

## How hashes are computed

```python
import hashlib

with open("artifacts/system-prompt.txt", "rb") as f:
    content = f.read()
artifact_hash = "sha256:" + hashlib.sha256(content).hexdigest()
```

See [Tutorial: Server-side verification](../../docs/tutorials/server-side-verification.md) for the full implementation.
