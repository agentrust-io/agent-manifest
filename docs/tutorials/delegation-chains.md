# Verify a Delegation Chain

Create two signed delegation hops for one receiving manifest, verify scope narrowing, and reject a correctly signed scope escalation. This local software example exercises the delegation primitive; it does not run an agent, authenticate a network peer, or verify a complete manifest.

## Run the example

Use the installation from the [first-manifest guide](../getting-started.md). Save this block as `delegation_example.py` and run `python delegation_example.py`.

```python
import copy
from datetime import datetime, timezone
from cryptography.exceptions import InvalidSignature
from agent_manifest import generate_ed25519
from agent_manifest._delegation import DelegationHopSigner, verify_delegation_chain

manifest_id = "019236ab-cdef-7000-8000-000000000002"
root = "spiffe://example.test/issuer"
delegate = "spiffe://example.test/delegate"
root_key, delegate_key = generate_ed25519(), generate_ed25519()
# Recipient-owned trust configuration, retained separately from the chain.
trusted_keys = {root: root_key.public_bytes, delegate: delegate_key.public_bytes}
stamp = datetime.now(timezone.utc).isoformat()

def signed_hop(index, principal, key, tools):
    hop = {
        "hop": index,
        "principal_id": principal,
        "principal_type": "agent",
        "delegated_at": stamp,
        "scope_grant": {
            "tools": tools,
            "data_classifications": ["public"],
            "constraints": [],
            "ttl_seconds": 600,
            "max_delegation_depth": 1,
        },
    }
    hop["delegation_signature"] = DelegationHopSigner(key).sign_hop(
        **hop, manifest_id=manifest_id,
    )
    return hop

chain = [
    signed_hop(0, root, root_key, ["search", "summarize"]),
    signed_hop(1, delegate, delegate_key, ["search"]),
]
verify_delegation_chain(chain, trusted_keys, manifest_id, manifest_issuer=root)
print("PASS: two signed hops with narrowed scope")

escalated = copy.deepcopy(chain)
# This signature is valid: rejection must come from scope narrowing.
escalated[1] = signed_hop(1, delegate, delegate_key, ["search", "write"])
try:
    verify_delegation_chain(escalated, trusted_keys, manifest_id, manifest_issuer=root)
except ValueError as error:
    assert "Scope laundering" in str(error)
    print("PASS: signed scope escalation rejected")
else:
    raise RuntimeError("Scope escalation was accepted")

try:
    verify_delegation_chain(
        chain, trusted_keys, "019236ab-cdef-7000-8000-000000000003",
        manifest_issuer=root,
    )
except InvalidSignature:
    print("PASS: replay under another manifest ID rejected")
else:
    raise RuntimeError("Cross-manifest replay was accepted")
```

Expect three `PASS` lines. Every hop signs the same receiving `manifest_id`. Copying a hop signed for a different ID into this chain invalidates its signature; changing the receiving manifest requires fresh authorized hop signatures.

## Connect it to manifest verification

Attach the chain to a complete manifest whose issuer matches the trusted root identity. For v0.1 JSON, `Ed25519Signer.sign()` returns a signature block; assign it to the manifest's `signature` field. For v0.2, use the COSE signing path. Supply trusted issuer keys, `delegation_public_keys`, current revocation state, and independently observed runtime artifacts to `verify_manifest()`. Set `require_delegation=True` when absence must fail.

The primitive compares scopes between adjacent hops and binds them to the supplied manifest ID. The application must establish the root's original authority and authorize the requested operation. An empty chain returns without a primitive error, so the full verification policy must enforce presence when required. This example does not demonstrate wall-clock expiry enforcement or revocation propagation.

See [server-side verification](server-side-verification.md) and [approval workflows](hitl-approval-workflows.md) for the receiving application's other checks.
