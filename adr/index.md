# Architecture Decision Records

Each major design decision in the Agent Manifest Specification is recorded here with its rationale, alternatives considered, and consequences. ADRs are immutable once accepted - superseded decisions get a new ADR that references the old one.

| ADR                                                                                                | Title                                                                                    | Status   |
| -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | -------- |
| [0001](https://manifest.agentrust-io.com/adr/0001-rfc8785-canonical-json/index.md)                 | RFC 8785 (JCS) for canonical serialization                                               | Accepted |
| [0002](https://manifest.agentrust-io.com/adr/0002-ed25519-standard-profile/index.md)               | Ed25519 as the standard cryptographic profile                                            | Accepted |
| [0003](https://manifest.agentrust-io.com/adr/0003-rfc9162-merkle-domain-separation/index.md)       | RFC 9162 Merkle tree with domain separation                                              | Accepted |
| [0004](https://manifest.agentrust-io.com/adr/0004-pydantic-v2-schema-modeling/index.md)            | Pydantic v2 for schema modeling in the Python SDK                                        | Accepted |
| [0005](https://manifest.agentrust-io.com/adr/0005-ml-dsa-hybrid-signature/index.md)                | ML-DSA-65 and hybrid Ed25519+ML-DSA-65 signature support                                 | Accepted |
| [0006](https://manifest.agentrust-io.com/adr/0006-hitl-approval-mechanism/index.md)                | Human-in-the-Loop (HITL) embedded approval record design                                 | Accepted |
| [0007](https://manifest.agentrust-io.com/adr/0007-revocation-json-lines-crl/index.md)              | JSON-Lines append-only CRL as the SDK revocation format                                  | Accepted |
| [0008](https://manifest.agentrust-io.com/adr/0008-conformance-level-design/index.md)               | Four conformance levels (0–3) rather than binary conformant/non-conformant               | Accepted |
| [0009](https://manifest.agentrust-io.com/adr/0009-spiffe-uri-agent-identity/index.md)              | SPIFFE URIs as the canonical identity format for agent_id and issuer                     | Accepted |
| [0010](https://manifest.agentrust-io.com/adr/0010-runtime-attestation-freshness-proofs/index.md)   | Runtime attestation freshness proofs via caller-controlled REPORT_DATA                   | Accepted |
| [0011](https://manifest.agentrust-io.com/adr/0011-signature-envelope/index.md)                     | The manifest is a signed document, not a JWT/JOSE profile; envelope moves to COSE_Sign1  | Accepted |
| [0012](https://manifest.agentrust-io.com/adr/0012-context-uri-moved-to-controlled-domain/index.md) | `@context` URI moves to a domain we control; v0.1 URL withdrawn, consumers cut over      | Accepted |
| [0013](https://manifest.agentrust-io.com/adr/0013-cbor-library-for-cose/index.md)                  | Take a CBOR library, not a COSE library; the COSE structures are built in-repo           | Accepted |
| [0014](https://manifest.agentrust-io.com/adr/0014-fully-specified-ed25519-code-point/index.md)     | Sign with the fully-specified Ed25519 code point (-19); keep verifying the deprecated -8 | Accepted |

To propose a new ADR, open a GitHub issue using the [spec change template](https://github.com/agentrust-io/agent-manifest/issues/new?template=spec_change.md) and follow the [ADR template](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0000-template.md).

______________________________________________________________________

For practical implementation guidance that corresponds to these decisions, see the [tutorials](https://manifest.agentrust-io.com/tutorials/index.md): [HITL approval workflows](https://manifest.agentrust-io.com/tutorials/hitl-approval-workflows/index.md) (ADR-0006), [revocation and key rotation](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md) (ADR-0007), [hardware attestation](https://manifest.agentrust-io.com/tutorials/hardware-attestation/index.md) (ADR-0008), and [server-side verification](https://manifest.agentrust-io.com/tutorials/server-side-verification/index.md).
