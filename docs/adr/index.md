# Architecture Decision Records

Each major design decision in the Agent Manifest Specification is recorded here with its rationale, alternatives considered, and consequences. ADRs are immutable once accepted — superseded decisions get a new ADR that references the old one.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rfc8785-canonical-json.md) | RFC 8785 (JCS) for canonical serialization | Accepted |
| [0002](0002-ed25519-standard-profile.md) | Ed25519 as the standard cryptographic profile | Accepted |
| [0003](0003-rfc9162-merkle-domain-separation.md) | RFC 9162 Merkle tree with domain separation | Accepted |
| [0004](0004-pydantic-v2-schema-modeling.md) | Pydantic v2 for schema modeling in the Python SDK | Accepted |
| [0005](0005-ml-dsa-hybrid-signatures.md) | ML-DSA-65 and hybrid Ed25519+ML-DSA-65 signatures | Accepted |
| [0006](0006-hitl-approval-mechanism.md) | HITL approval mechanism design | Accepted |
| [0007](0007-revocation-crl-format.md) | Append-only JSON-Lines CRL for manifest revocation | Accepted |
| [0008](0008-conformance-levels.md) | Four conformance levels (0–3) | Accepted |
| [0009](0009-spiffe-uri-agent-identity.md) | SPIFFE URIs for agent identity | Accepted |

To propose a new ADR, open a GitHub issue using the [spec change template](https://github.com/agentrust-io/agent-manifest/issues/new?template=spec_change.md) and follow the [ADR template](0000-template.md).

---

For practical implementation guidance that corresponds to these decisions, see the [tutorials](../tutorials/index.md): [HITL approval workflows](../tutorials/hitl-approval-workflows.md) (ADR-0006), [revocation and key rotation](../tutorials/revocation-and-key-rotation.md) (ADR-0007), [hardware attestation](../tutorials/hardware-attestation.md) (ADR-0008), and [server-side verification](../tutorials/server-side-verification.md).
