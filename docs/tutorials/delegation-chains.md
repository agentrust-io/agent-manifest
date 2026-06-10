# A2A delegation chains

Agent-to-agent (A2A) delegation lets a root issuer grant a sub-agent a **scoped subset** of its permissions  -  cryptographically bound and verifiable at every hop. After completing this tutorial you will be able to:

- Build a two-hop delegation chain: root issuer → delegate → sub-delegate
- Sign each hop with the delegating principal's key
- Verify the full chain and detect scope laundering
- Understand what the verifier rejects at each failure mode

## Prerequisites

```bash
pip install "agent-manifest[cli]"
```

## Conceptual model

```
Root issuer (tools: [search, summarize, write])
  └─ Delegate agent (tools: [search, summarize])   ← hop 0: scope narrowed
       └─ Sub-delegate agent (tools: [search])      ← hop 1: narrowed again
```

Each hop is signed by the **delegating** principal. The sub-agent cannot claim tools the parent did not grant  -  the verifier enforces this at every hop.

---

## Step 1: Generate keypairs for each principal

```python
from agent_manifest import generate_ed25519

root_kp = generate_ed25519()        # root issuer
delegate_kp = generate_ed25519()    # delegate agent
sub_kp = generate_ed25519()         # sub-delegate agent
```

---

## Step 2: Build the root manifest

The root manifest declares the full scope the issuer authorises.

```python
from agent_manifest import Manifest, ArtifactBindings, CryptoProfile
from agent_manifest._types import ManifestId
from agent_manifest._signing import Ed25519Signer
from agent_manifest._delegation import DelegationHopSigner
from datetime import datetime, timedelta, timezone
import base64

now = datetime.now(timezone.utc)

root_manifest = Manifest(
    manifest_id=str(ManifestId.generate()),
    agent_id="spiffe://trust.example/agent/orchestrator",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=8),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(),
    # No delegation_chain on the root  -  it IS the root
    delegation_chain=[],
)

signer = Ed25519Signer(root_kp)
signed_root = signer.sign(root_manifest.model_dump(mode="json"))
```

---

## Step 3: Build the delegate hop

The delegate agent creates a manifest that references the root manifest and adds a delegation hop signed by the **root issuer**.

```python
from agent_manifest._delegation import DelegationHopSigner

hop_signer = DelegationHopSigner(keypair=root_kp)

delegate_manifest_id = str(ManifestId.generate())

# The root issuer signs hop 0  -  granting a subset of its tools
hop0_scope = {
    "tools": ["search", "summarize"],          # subset of root's [search, summarize, write]
    "data_classifications": ["public", "internal"],
    "max_delegation_depth": 2,
    "approval_required": False,
}

hop0_sig = hop_signer.sign_hop(
    hop=0,
    principal_id="spiffe://trust.example/agent/orchestrator",
    principal_type="agent",
    delegated_at=now.isoformat(),
    scope_grant=hop0_scope,
    manifest_id=delegate_manifest_id,
)

delegate_manifest = Manifest(
    manifest_id=delegate_manifest_id,
    agent_id="spiffe://trust.example/agent/researcher",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=8),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(),
    delegation_chain=[{
        "hop": 0,
        "principal_id": "spiffe://trust.example/agent/orchestrator",
        "principal_type": "agent",
        "delegated_at": now.isoformat(),
        "scope_grant": hop0_scope,
        "delegation_signature": hop0_sig,
    }],
)

delegate_signer = Ed25519Signer(delegate_kp)
signed_delegate = delegate_signer.sign(delegate_manifest.model_dump(mode="json"))
```

---

## Step 4: Build the sub-delegate hop

The sub-delegate's manifest adds a second hop signed by the **delegate agent**  -  again narrowing the scope.

```python
sub_manifest_id = str(ManifestId.generate())

# The delegate agent signs hop 1  -  granting only [search] from its [search, summarize]
hop1_scope = {
    "tools": ["search"],                        # subset of delegate's [search, summarize]
    "data_classifications": ["public"],         # narrowed from ["public", "internal"]
    "max_delegation_depth": 2,
    "approval_required": False,
}

delegate_hop_signer = DelegationHopSigner(keypair=delegate_kp)
hop1_sig = delegate_hop_signer.sign_hop(
    hop=1,
    principal_id="spiffe://trust.example/agent/researcher",
    principal_type="agent",
    delegated_at=now.isoformat(),
    scope_grant=hop1_scope,
    manifest_id=sub_manifest_id,
)

sub_manifest = Manifest(
    manifest_id=sub_manifest_id,
    agent_id="spiffe://trust.example/agent/data-fetcher",
    version="0.1",
    issued_at=now,
    expires_at=now + timedelta(hours=8),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(),
    delegation_chain=[
        # Carry the full chain forward
        {
            "hop": 0,
            "principal_id": "spiffe://trust.example/agent/orchestrator",
            "principal_type": "agent",
            "delegated_at": now.isoformat(),
            "scope_grant": hop0_scope,
            "delegation_signature": hop0_sig,
        },
        {
            "hop": 1,
            "principal_id": "spiffe://trust.example/agent/researcher",
            "principal_type": "agent",
            "delegated_at": now.isoformat(),
            "scope_grant": hop1_scope,
            "delegation_signature": hop1_sig,
        },
    ],
)

sub_signer = Ed25519Signer(sub_kp)
signed_sub = sub_signer.sign(sub_manifest.model_dump(mode="json"))
```

---

## Step 5: Verify the chain

```python
from agent_manifest._delegation import verify_delegation_chain

# Build a registry of public keys for all principals in the chain
public_keys = {
    "spiffe://trust.example/agent/orchestrator": root_kp.public_bytes,
    "spiffe://trust.example/agent/researcher":   delegate_kp.public_bytes,
}

# Verify the sub-delegate's chain
verify_delegation_chain(
    delegation_chain=signed_sub["delegation_chain"],
    public_keys=public_keys,
    manifest_id=sub_manifest_id,
)
print("Chain valid")  # reaches here only if all signatures and scopes check out
```

`verify_delegation_chain` raises on the first failure:

| Error | Cause |
|-------|-------|
| `InvalidSignature` | A hop signature is invalid |
| `ValueError: Scope laundering` | Child claims tools or data classes not granted by parent |
| `ValueError: depth exceeded` | Chain is deeper than `max_delegation_depth` on hop 0 |
| `ValueError: wrong hop index` | Hops are not sequential (0, 1, 2, …) |

---

## Failure modes

### Scope laundering (rejected)

```python
# Attacker tries to claim "write" which was never granted past hop 0
bad_scope = {
    "tools": ["search", "write"],   # "write" is NOT in hop 0's grant
    "max_delegation_depth": 2,
}
bad_sig = delegate_hop_signer.sign_hop(
    hop=1, principal_id="...", principal_type="agent",
    delegated_at=now.isoformat(), scope_grant=bad_scope,
    manifest_id=sub_manifest_id,
)
# verify_delegation_chain raises:
# ValueError: Scope laundering at hop 1: child claims tools {'write'} not granted by parent
```

### Depth exceeded (rejected)

```python
# Root grants max_delegation_depth=1 but chain has 2 hops
# verify_delegation_chain raises:
# ValueError: Delegation chain depth 2 exceeds root max_delegation_depth 1
```

### Wrong key (rejected)

```python
# Attacker signs hop 0 with their own key, not the root issuer's key
# verify_delegation_chain raises: InvalidSignature
```

---

## What's next

- [Tutorial: Server-side verification](server-side-verification.md)  -  verify delegation chains at the relying party
- [Tutorial: HITL approval workflows](hitl-approvals.md)  -  require human sign-off within a delegation chain
- [Examples repository](https://github.com/agentrust-io/examples)
