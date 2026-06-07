# Architecture Decision Records

Each major design decision in the Agent Manifest Specification is recorded here with its rationale, alternatives considered, and consequences. ADRs are immutable once accepted — superseded decisions get a new ADR that references the old one.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rfc8785-canonical-json.md) | RFC 8785 (JCS) for canonical serialization | Accepted |
| [0002](0002-ed25519-standard-profile.md) | Ed25519 as the standard cryptographic profile | Accepted |
| [0003](0003-rfc9162-merkle-domain-separation.md) | RFC 9162 Merkle tree with domain separation | Accepted |
| [0004](0004-pydantic-v2-schema-modeling.md) | Pydantic v2 for schema modeling in the Python SDK | Accepted |
| [0005](0005-ml-dsa-hybrid-signature.md) | ML-DSA-65 and hybrid Ed25519+ML-DSA-65 signature support | Accepted |
| [0006](0006-hitl-approval-mechanism.md) | Human-in-the-Loop (HITL) embedded approval record design | Accepted |
| [0007](0007-revocation-json-lines-crl.md) | JSON-Lines append-only CRL as the SDK revocation format | Accepted |
| [0008](0008-conformance-level-design.md) | Four conformance levels (0–3) rather than binary conformant/non-conformant | Accepted |
| [0009](0009-spiffe-uri-for-agent-identity.md) | SPIFFE URIs as the canonical identity format for agent_id and issuer | Accepted |

To propose a new ADR, open a GitHub issue using the [spec change template](https://github.com/agentrust-io/agent-manifest/issues/new?template=spec_change.md) and follow the [ADR template](0000-template.md).
