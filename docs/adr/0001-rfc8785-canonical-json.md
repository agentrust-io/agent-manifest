# ADR-0001: Use RFC 8785 (JCS) for all canonical serialization

**Status**: Accepted  
**Date**: 2026-05-01  
**Spec section**: Section 2.3, Section 4.3

## Context

The manifest signature pre-image, all artifact hash inputs, and Merkle tree leaf nodes require a deterministic byte representation of JSON objects. Multiple options exist: JSON-LD normalization (RDNA), canonical JSON (various informal specs), JCS (RFC 8785), and CBOR.

The spec must produce identical byte sequences across Python, TypeScript, Go, and .NET implementations without shared library dependencies.

## Decision

Use RFC 8785 JSON Canonicalization Scheme (JCS) for all canonical serialization. The `@context` and `@type` JSON-LD fields are treated as ordinary JSON fields for canonicalization purposes  -  JSON-LD RDF dataset normalization is explicitly prohibited.

## Rationale

- RFC 8785 is a published IETF standard with clear normative text and test vectors
- Widely implemented: reference implementations exist in Python (`jcs`), JavaScript (`canonicalize`), Go (`go-jcs`), Java, and .NET
- Simpler than JSON-LD RDNA: no RDF graph normalization, no blank node renaming, no triple sorting  -  just Unicode code point key ordering and IEEE 754 float normalization
- The JCS test vector (Appendix D of the spec) is machine-verifiable across all SDK implementations
- RDNA would require a full JSON-LD processor in each SDK, adding a heavyweight dependency

## Alternatives considered

**JSON-LD RDNA (GPN-09)**: Full RDF dataset normalization. Rejected because it requires a JSON-LD processor, handles blank node renaming (irrelevant to our use case), and produces different output from JCS  -  mixing the two would create interoperability failures.

**Informal "canonical JSON"**: Various ad-hoc schemes (sorted keys, no whitespace). Rejected because there is no normative specification, making cross-implementation verification impossible.

**CBOR**: Binary format, no JSON compatibility. Rejected because the manifest is a JSON-LD document and binary serialization would require a separate encoding step.

## Consequences

- All SDK implementations must implement RFC 8785. This is a hard requirement for conformance test AM-CRYPTO-001.
- Null-valued optional fields must be excluded from the canonical form (not included as `null`). This is specified in Section 2.3 and enforced in AM-BIND tests.
- Float handling follows RFC 8785 §3.2.2.3 (ECMAScript number formatting). NaN and Infinity are rejected.

## References

- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
- Spec Appendix D: RFC 8785 test vector
