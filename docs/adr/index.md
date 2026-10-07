# Architecture Decision Records

This page lists the design decisions behind Agent Manifest. Each one is written up as an Architecture Decision Record (ADR): a short note on what was decided, what else was considered, and what follows from it. Read them when you want to know why the format works the way it does; you do not need them to use the SDK.

An accepted ADR is never edited to reverse it. A decision that replaces an earlier one gets a new ADR that points back to the old one.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-rfc8785-canonical-json.md) | RFC 8785 (JCS) for canonical serialization | Accepted |
| [0002](0002-ed25519-standard-profile.md) | Ed25519 as the standard cryptographic profile | Accepted |
| [0003](0003-rfc9162-merkle-domain-separation.md) | RFC 9162 Merkle tree with domain separation | Accepted |
| [0004](0004-pydantic-v2-schema-modeling.md) | Pydantic v2 for schema modeling in the Python SDK | Accepted |
| [0005](0005-ml-dsa-hybrid-signature.md) | ML-DSA-65 and hybrid Ed25519+ML-DSA-65 signature support | Accepted |
| [0006](0006-hitl-approval-mechanism.md) | Human-in-the-Loop (HITL) embedded approval record design | Accepted |
| [0007](0007-revocation-json-lines-crl.md) | JSON-Lines append-only CRL as the SDK revocation format | Accepted |
| [0008](0008-conformance-level-design.md) | Four conformance levels (0 to 3) rather than binary conformant/non-conformant | Accepted |
| [0009](0009-spiffe-uri-agent-identity.md) | SPIFFE URIs as the canonical identity format for agent_id and issuer | Accepted |
| [0010](0010-runtime-attestation-freshness-proofs.md) | Runtime attestation freshness proofs via caller-controlled REPORT_DATA | Accepted |
| [0011](0011-signature-envelope.md) | The manifest is a signed document, not a JWT/JOSE profile; envelope moves to COSE_Sign1 | Accepted |
| [0012](0012-context-uri-moved-to-controlled-domain.md) | `@context` URI moves to a domain we control; v0.1 URL withdrawn, consumers cut over | Accepted |
| [0013](0013-cbor-library-for-cose.md) | Take a CBOR library, not a COSE library; the COSE structures are built in-repo | Accepted |
| [0014](0014-fully-specified-ed25519-code-point.md) | Sign with the fully-specified Ed25519 code point (-19); keep verifying the deprecated -8 | Accepted |
| [0015](0015-agent-plugins-manifest-reference.md) | Agent Plugins manifest reference | Accepted |

To propose a new ADR, open a GitHub issue using the [spec change template](https://github.com/agentrust-io/agent-manifest/issues/new?template=spec_change.md) and follow the [ADR template](https://github.com/agentrust-io/agent-manifest/blob/main/docs/adr/0000-template.md).

---

For practical implementation guidance that corresponds to these decisions, see the [tutorials](../tutorials/index.md): [HITL approval workflows](../tutorials/hitl-approval-workflows.md) (ADR-0006), [revocation and key rotation](../tutorials/revocation-and-key-rotation.md) (ADR-0007), [hardware attestation](../tutorials/hardware-attestation.md) (ADR-0008), and [server-side verification](../tutorials/server-side-verification.md).
