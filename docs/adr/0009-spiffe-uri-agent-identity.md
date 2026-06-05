# ADR-0009: SPIFFE URIs for agent identity (`agent_id` and `issuer`)

**Status**: Accepted  
**Date**: 2026-05-26  
**Spec section**: Section 2.2 (Identity Fields)

## Context

Every manifest must identify two principals:

1. **The agent** (`agent_id`) — the workload whose behavior the manifest governs
2. **The issuer** (`issuer`) — the authority that signed the manifest

These identifiers must be:
- Globally unique
- Verifiable (a relying party can confirm the identifier is authentic)
- Stable across restarts and re-deployments
- Interoperable with existing infrastructure-level identity systems (service meshes, PKI, cloud IAM)

Multiple identity schemes exist: SPIFFE, DID methods (did:key, did:web, did:ethr), URNs, X.509 Subject DNs, and opaque UUIDs.

## Decision

Use **SPIFFE URIs** (`spiffe://trust-domain/path`) as the canonical identity format for both `agent_id` and `issuer`. All other formats are rejected at validation time by the Python SDK.

Valid example:
```
spiffe://trust.example/agent/kyc-processor/prod
```

The trust domain (`trust.example` in the example) is operated by the deploying organization and is registered out-of-band. The path component identifies the specific workload within that trust domain.

## Rationale

**SPIFFE is the established standard for workload identity.** It is used natively by Istio, Envoy, SPIRE, Cilium, and Linkerd — the most widely deployed service mesh and zero-trust infrastructure projects. An agent running alongside any of these already has a SPIFFE identity available through the SPIFFE Workload API (X.509-SVID). Reusing this identity means zero additional configuration for the majority of Kubernetes and cloud-native deployments.

**Trust domain semantics are explicit.** `spiffe://trust.example/agent/kyc` makes it unambiguous that the trust.example organization vouches for this identity. An identifier like `agent-kyc-prod` carries no such claim. This matters for multi-org delegation chains: `spiffe://bank.example/agent/payments` cannot impersonate `spiffe://regulator.example/agent/auditor` because the trust domains are structurally distinct.

**Path structure enables fleet organization without a central registry.** The path component under the trust domain is controlled by the deployer. `spiffe://corp.example/region/us-east/service/fraud-detector/env/prod` encodes organization, geography, service, and environment in a single identifier that is human-readable, hierarchical, and unique.

**SPIFFE URIs are infrastructure-neutral.** Unlike X.509 Subject DNs (which require a CA hierarchy) or DIDs (which often require a blockchain or external resolver), SPIFFE URIs are resolved by the deployer's own SPIRE server. An air-gapped deployment can mint SPIFFE identities without external dependencies.

## Alternatives considered

**did:key**: A self-sovereign DID derived from a public key. No registry or infrastructure required — the DID is the public key. Rejected because a `did:key` encodes the current signing key, not the logical identity of the agent. Key rotation would change the agent's identity, breaking all existing trust relationships and delegation chains that reference the old DID. An agent's identity should be stable across key rotations.

**did:web**: A DID resolved from a domain (`did:web:trust.example`). Requires the DID document to be hosted at `https://trust.example/.well-known/did.json`. Rejected because it introduces an HTTP resolution dependency at verification time and couples the agent's identity to the domain's DNS and TLS availability.

**did:ethr / blockchain DIDs**: Identity anchored on Ethereum or another blockchain. Rejected categorically — blockchain anchoring introduces gas costs, transaction latency, and external infrastructure dependencies into a security-critical path. Not suitable for regulated environments.

**X.509 Subject DN** (`CN=kyc-agent, O=Corp, C=US`): The identity format used in mTLS certificates. Rejected because Subject DNs have no standardized path semantics, are not URL-safe, and vary by CA policy. Extracting the workload identity from an X.509 Subject DN reliably requires CA-specific parsing.

**Opaque UUID**: A random UUID assigned at registration. Rejected because it carries no human-interpretable information, cannot encode organizational hierarchy, and requires a central registry to map UUIDs to actual identities.

## Consequences

- The Python SDK validates `agent_id` and `issuer` as SPIFFE URIs at `Manifest` construction time. Any string that does not match `spiffe://[trust-domain]/[path]` raises a `ValidationError`.
- Deployers who do not run a SPIRE server must still use the SPIFFE URI format — they can mint identities manually (for development) or use a lightweight SPIFFE implementation. The format is required even if SPIRE is not used.
- Multi-org delegation chains are naturally expressed: the root issuer SPIFFE URI and the delegate SPIFFE URI come from different trust domains, making cross-org delegation visually and structurally distinct from intra-org delegation.
- The trust domain is not verified by the SDK — the spec does not mandate a SPIRE integration. Verification that a SPIFFE URI is authentic (i.e., backed by a real SPIRE certificate) is out of scope for Level 0 and Level 1; it is addressed by the mTLS transport layer at Level 2+.

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIRE — SPIFFE Runtime Environment](https://spiffe.io/docs/latest/spire-about/)
- [RFC 9110 §4](https://www.rfc-editor.org/rfc/rfc9110#section-4) — URI format
- Spec Section 2.2: Identity field validation rules
