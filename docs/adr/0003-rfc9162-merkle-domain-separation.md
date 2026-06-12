# ADR-0003: RFC 9162 Merkle tree construction with domain separation

**Status**: Accepted  
**Date**: 2026-05-10  
**Spec section**: Section 4.1.1, Section 3.2.3 (tool catalog hash), Section 3.2.5 (RAG corpus)

## Context

The tool manifest catalog hash and the RAG corpus hash both require a Merkle tree over a set of items (tool schemas and corpus documents respectively). The Merkle construction must be specified precisely to ensure cross-implementation reproducibility and to prevent second-preimage attacks.

## Decision

Use the RFC 9162 (Certificate Transparency v2) Merkle tree construction with explicit domain separation:

- Leaf nodes: `SHA-256(0x00 || leaf_data)`
- Internal nodes: `SHA-256(0x01 || left_hash || right_hash)`

Leaf data for tool entries: RFC 8785 canonical JSON of the tool descriptor (schema + description, sorted by tool name).  
Leaf data for corpus documents: RFC 8785 canonical JSON of the document descriptor (hash + identifier + ingested_at).

## Rationale

- RFC 9162 is a published IETF standard for Merkle tree construction, used in Certificate Transparency  -  a deployed, audited system
- The `0x00`/`0x01` domain separation prefix prevents second-preimage attacks where an attacker constructs an internal node that collides with a leaf node
- Without domain separation, a tree with N leaves has the same root as a tree with N/2 "leaves" that are actually internal node hashes  -  the domain prefix makes these structurally distinct
- RFC 9162 construction is deterministic given a fixed leaf ordering (lexicographic by tool name / document identifier)

## Alternatives considered

**Simple concatenation Merkle (no domain separation)**: Vulnerable to second-preimage attacks as described above. Rejected.

**BLAKE3 Merkle**: BLAKE3 has built-in domain separation for its tree construction. Rejected because BLAKE3 is not yet in the standard library of all target languages, and SHA-256 is sufficient for this use case.

**Flat hash (hash of concatenated hashes)**: Not a Merkle tree  -  does not support efficient membership proofs. Rejected because the spec's design supports future membership proof extensions.

## Consequences

- The `0x00` prefix on leaf nodes and `0x01` prefix on internal nodes are mandatory. Implementations that omit them will fail conformance test AM-BIND-015.
- Leaf ordering must be deterministic: tool entries sorted by `tool_id` (lexicographic, Unicode code point order, same as RFC 8785 key ordering). Corpus documents sorted by `document_id`.
- Empty trees (no tools, no corpus documents) are represented by the SHA-256 of the empty string: `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## References

- [RFC 9162  -  Certificate Transparency Version 2.0, Section 2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1)
