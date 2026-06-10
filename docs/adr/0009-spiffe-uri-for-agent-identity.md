# ADR-0009: SPIFFE URIs as the canonical identity format for `agent_id` and `issuer`

**Status**: Accepted  
**Date**: 2026-06-07  
**Spec section**: Section 2.2 (Identity Fields)

## Context

Every manifest must identify two principals:

1. **The agent** (`agent_id`)  -  the workload whose behavior the manifest governs
2. **The issuer** (`issuer`)  -  the authority that signed the manifest

These identifiers must be:
- Globally unique without a central registry
- Structurally meaningful (carrying trust domain context, not opaque bytes)
- Stable across key rotations and redeployments
- Interoperable with existing zero-trust infrastructure (service meshes, cloud IAM, enterprise PKI)

Multiple identity schemes exist: SPIFFE, DID methods (did:key, did:web, did:ethr), plain URNs, X.509 Subject DNs, and opaque UUIDs.

## Decision

Use **SPIFFE URIs** (`spiffe://trust-domain/path`) as the canonical identity format for both `agent_id` and `issuer`. All other formats are rejected at validation time by the Python SDK.

Valid example:
```
spiffe://payments.acme.com/agents/settlement-agent-v2
```

The trust domain (`payments.acme.com`) is the org-level PKI boundary, operated by the deploying organization and registered out-of-band. The path component identifies the specific workload within that trust domain using slash-delimited segments.

SDK validation rules enforced at `Manifest` construction time:
- Must start with `spiffe://`
- No URI fragment (`#`)  -  fragments have no meaning in SPIFFE
- No query string (`?`)  -  SPIFFE URIs are path-only
- Trust domain must be a valid hostname (RFC 1123)
- Path must be slash-delimited segments with no empty components

Multi-org deployments follow the SPIFFE Federation specification: trust domain federation is established at the infrastructure layer (SPIRE server-to-server federation), not at the manifest layer.

## Rationale

**SPIFFE is the established standard for workload identity in zero-trust infrastructure.** It is used natively by Istio, Linkerd, Envoy, SPIRE, Cilium, and HashiCorp Vault's identity framework. It is the default identity format in Kubernetes SPIFFE/SPIRE integration. An agent running alongside any of these already has a SPIFFE identity available through the SPIFFE Workload API (X.509-SVID). Reusing this identity requires zero additional configuration for the majority of cloud-native deployments.

**Trust domain semantics are explicit and structurally enforced.** `spiffe://bank.example/agents/payments` makes it unambiguous that `bank.example` vouches for this identity. An identifier like `agent-payments-prod` carries no such claim. This matters critically for multi-org delegation chains: `spiffe://bank.example/agent/payments` cannot impersonate `spiffe://regulator.example/agent/auditor` because the trust domains are structurally distinct and cannot be confused by string manipulation.

**SPIFFE URIs are infrastructure-neutral.** Unlike X.509 Subject DNs (which require a CA hierarchy) or DIDs (which often require a blockchain or external HTTP resolver), SPIFFE URIs are resolved by the deployer's own SPIRE server. An air-gapped deployment can mint SPIFFE identities without external network access.

**Path structure enables fleet organization without a central registry.** The path component under the trust domain is controlled by the deployer. `spiffe://corp.example/region/us-east/service/fraud-detector/env/prod` encodes organization, geography, service, and environment in a single identifier that is human-readable, hierarchical, and unique without requiring coordination with any external party.

**SVID issuance provides a standard mechanism for backing SPIFFE identities cryptographically.** A SPIFFE Verifiable Identity Document (SVID) is an X.509 certificate or JWT that proves a workload holds a specific SPIFFE URI, issued by the deployer's SPIRE server. At Level 2+, the mTLS transport layer provides SVID-backed proof that the agent presenting the manifest is the same workload named in `agent_id`.

## Alternatives considered

**DID:key**: A self-sovereign DID derived from a public key (`did:key:z6Mk...`). No registry or infrastructure required. Rejected because `did:key` encodes the current signing key, not the logical identity of the agent. Key rotation would change the agent's `agent_id`, breaking all delegation chains, trust relationships, and policy rules that reference the old DID. An agent's logical identity must be stable across key rotations.

**DID:web**: A DID resolved from a domain (`did:web:trust.example`). Requires hosting a DID document at `https://trust.example/.well-known/did.json`. Rejected because it introduces an HTTP resolution dependency at verification time and couples the agent's identity to the domain's DNS and TLS availability  -  exactly the kind of online dependency the embedded design of the manifest (ADR-0006, ADR-0007) is designed to avoid.

**DID:ethr and blockchain-anchored DIDs**: Identity anchored on Ethereum or another blockchain. Rejected categorically: blockchain anchoring introduces gas costs, transaction latency, and external infrastructure dependencies into a security-critical verification path. Not suitable for regulated environments or high-throughput verification.

**Plain URNs (`urn:agent:...`)**: RFC 8141 URNs with a custom namespace. Rejected because URNs have no standard resolution or federation mechanism  -  there is no urn:agent NID assigned by IANA, no standard way to express trust domains, and no interoperability story with existing zero-trust infrastructure. SPIFFE provides all of this.

**Opaque UUIDs**: A random UUID assigned at registration. Rejected because UUIDs carry no trust domain context  -  a UUID from one organization is syntactically identical to one from another. UUIDs require a central registry to map them to actual identities and offer no structural guarantee of uniqueness across organizations.

**X.509 Subject DN** (`CN=kyc-agent, O=Corp, C=US`): The identity format used in mTLS certificates. Rejected because Subject DNs have no standardized path semantics, are not URL-safe, vary in encoding by CA policy, and require CA-specific parsing to extract a workload identifier reliably.

## Consequences

- The Python SDK validates `agent_id` and `issuer` as SPIFFE URIs at `Manifest` construction time. Any value that does not match `spiffe://[trust-domain]/[path]` raises `ValidationError`.
- Deployers who do not run a SPIRE server must still use the SPIFFE URI format. They can mint identities manually for development or use a lightweight SPIFFE implementation. The syntactic format is required even if full SVID validation is not in use.
- SVID-backed verification of SPIFFE URIs (confirming that the presenting workload genuinely holds the identity) is out of scope for Level 0 and Level 1. It is addressed by the mTLS transport layer at Level 2+, where the X.509-SVID chain is checked against the trust anchor.
- Multi-org delegation chains are naturally expressed and visually distinct: `spiffe://bank.example/agent/payments` delegating to `spiffe://vendor.example/agent/processor` makes the cross-org boundary obvious. Intra-org delegation (`spiffe://corp.example/agent/root` to `spiffe://corp.example/agent/worker`) is visually distinct from cross-org.

## References

- [SPIFFE Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE.md)
- [SPIFFE Federation Specification](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Federation.md)
- [SPIRE  -  SPIFFE Runtime Environment](https://spiffe.io/docs/latest/spire-about/)
- [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123)  -  Hostname syntax requirements
- [RFC 9110 §4](https://www.rfc-editor.org/rfc/rfc9110#section-4)  -  URI format reference
- ADR-0006: HITL approval mechanism (uses SPIFFE URIs for `approver_id`)
- ADR-0007: Revocation CRL (uses SPIFFE URIs for `revoked_by`)
- Spec Section 2.2: Identity field validation rules
