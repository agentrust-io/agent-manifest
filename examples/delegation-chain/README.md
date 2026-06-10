# A2A delegation chain example

This example shows a two-hop A2A delegation chain:

```
Root issuer (spiffe://trust.acme.co/signing-authority)
  └── Orchestrator agent (hop 0)
        └── Executor agent (hop 1  -  sub-delegate)
```

## Files

| File | Description |
|------|-------------|
| `root-manifest.json` | The orchestrator's manifest with `delegation_policy` allowing sub-delegation |
| `delegate-manifest.json` | The executor's manifest  -  delegated from the orchestrator with narrowed scope |
| `sub-delegate-manifest.json` | A second-hop manifest  -  delegated from the executor, scope narrowed further |
| `verify.sh` | Demonstrates chain traversal and scope narrowing |

## Key fields

### `delegation_chain` in `delegate-manifest.json`

```json
{
  "hop": 0,
  "principal_id": "spiffe://trust.acme.co/agent/orchestrator/prod",
  "principal_type": "agent",
  "delegated_at": "2026-06-05T09:00:00Z",
  "scope_grant": {
    "tools": ["fetch_public_data", "run_analysis"],
    "data_classifications": ["public", "internal"],
    "max_delegation_depth": 1,
    "approval_required": false
  },
  "delegation_signature": "BASE64URL_PLACEHOLDER"
}
```

The `delegation_signature` is the Ed25519 signature of the orchestrator's key over the RFC 8785 canonical form of `{hop, manifest_id, principal_id, principal_type, delegated_at, scope_grant}`.

### Scope narrowing rule

Each hop may only claim a subset of the parent's `tools` and `data_classifications`. The `sub-delegate-manifest.json` demonstrates this: the executor grants only `fetch_public_data` (not `run_analysis`) and only `public` data (not `internal`).

The verifier raises `ValueError: Scope laundering` if a sub-delegate tries to claim broader scope.

## What a real delegation looks like

In production, the orchestrator agent calls `DelegationHopSigner.sign_hop()` at runtime and embeds the signed hop into the manifest before passing it to the executor. See [Tutorial: A2A delegation chains](../../docs/tutorials/delegation-chains.md) for the full implementation.
