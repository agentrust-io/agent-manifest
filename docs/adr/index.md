# Architecture Decision Records

Each major design decision in the Agent Manifest Specification is recorded here with its rationale, alternatives considered, and consequences. ADRs are immutable once accepted — superseded decisions get a new ADR that references the old one.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rfc8785-canonical-json.md) | RFC 8785 (JCS) for canonical serialization | Accepted |
| [0002](0002-ed25519-standard-profile.md) | Ed25519 as the standard cryptographic profile | Accepted |
| [0003](0003-rfc9162-merkle-domain-separation.md) | RFC 9162 Merkle tree with domain separation | Accepted |

To propose a new ADR, open a GitHub issue using the [spec change template](https://github.com/agentrust-io/agent-manifest/issues/new?template=spec_change.md) and follow the [ADR template](0000-template.md).
