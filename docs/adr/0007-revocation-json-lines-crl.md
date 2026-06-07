# ADR-0007: JSON-Lines append-only CRL as the SDK revocation format

**Status**: Accepted  
**Date**: 2026-06-07  
**Spec section**: Section 3.7 (Revocation)

## Context

A compromised agent — one whose signing key has leaked, whose behavior has been found malicious, or that has been decommissioned — must be stoppable without waiting for its manifest to expire naturally. The spec needs a revocation mechanism that:

1. Allows an authorised authority to revoke any manifest in under 60 seconds
2. Makes revocation records tamper-evident — a record cannot be added, removed, or modified undetected
3. Is queryable by a verifier without X.509 infrastructure or a heavyweight credential processing stack
4. Provides a working reference implementation for development with zero infrastructure dependency

## Decision

Use **append-only JSON-Lines (`.jsonl`)** as the CRL file format. Each line is a JSON-encoded `SignedRevocationRecord` containing: `manifest_id`, `revoked_at` (ISO 8601), `reason`, `revoked_by` (SPIFFE URI or DID of the revoking authority), `signer_key_id`, and `revocation_signature` (Ed25519 signature by the revoking authority over the canonical form of the preceding fields).

The revocation record is signed by the **revoking authority's key**, not the original manifest issuer's key.

The standard discovery endpoint follows RFC 8615 well-known URI conventions:

- `GET /.well-known/agent-manifest/revocation` — returns all records as JSON-Lines
- `GET /.well-known/agent-manifest/revocation/{manifest_id}` — returns one record or 404

`FileCRL` is the reference implementation for development and small-scale deployments. Production deployments must use a database-backed store (Postgres, Redis, DynamoDB, or equivalent). The choice of database is not prescribed by the spec.

## Rationale

**JSON-Lines for append-only semantics.** Each revocation is a single line appended atomically. No locking is needed between writers and readers — the file grows monotonically and existing entries are never modified. A CRL committed to a git repository is an immutable, auditable append log. Readers parse line-by-line, so a partial read of a large CRL is always consistent.

**O(1) append cost.** A naive single JSON array requires rewriting the entire file for each revocation — O(n) write cost. JSON-Lines appends are O(1) regardless of CRL size, making revocation latency independent of fleet size.

**Signed records prevent forgery.** Without a per-record signature, an attacker with write access to the CRL could add fictitious revocations or delete real ones. The signature over the canonical record fields means any field mutation invalidates the signature.

**Revoking authority is separate from manifest issuer.** A security team can revoke manifests signed by a compromised issuer key without needing access to that key. The revoking authority's public key can be distributed out-of-band and rotated independently of the manifest PKI.

**Discovery via `.well-known`.** RFC 8615 well-known URIs are the established mechanism for service metadata discovery. `/.well-known/agent-manifest/revocation` is locatable by any HTTP client without configuration; no SDK-level resolver is needed.

## Alternatives considered

**W3C Status List 2021 (bitstring revocation list)**: A compact bitstring where each bit represents one credential, keyed by a sequential index assigned at issuance time. Rejected because it requires coordination between the issuer and CRL operator at manifest issuance time (to assign the index), and introduces a dependency on the W3C Verifiable Credentials processing stack — a heavyweight dependency that conflicts with the spec's goal of JSON-native tooling.

**RFC 5280 X.509 CRL format**: DER-encoded binary with ASN.1 structure, the standard for X.509 certificate revocation. Rejected because the manifest ecosystem is JSON-native. Requiring ASN.1 parsing in every SDK (Python, TypeScript, Go, .NET) is a disproportionate dependency burden for what is fundamentally a simple revocation list.

**Single JSON array**: A JSON file containing a list of all revocation records. Rejected because appending to a JSON array requires reading and rewriting the entire file (O(n) write). JSON-Lines gives O(1) append with no locking requirement.

**OCSP (Online Certificate Status Protocol)**: Per-manifest online status check at verification time. Rejected because it requires an always-available OCSP responder (a high-availability infrastructure requirement), leaks information about which manifests are being verified to the OCSP operator, and cannot be used in air-gapped environments. JSON-Lines CRL can be cached and served from a CDN with a defined TTL.

## Consequences

- `FileCRL` is explicitly a development tool. It is not suitable for multi-process or high-availability deployments. The `create_crl_router()` docstring and all documentation must state this clearly. Production deployments must implement a persistent database-backed store.
- The CRL is append-only by design. There is no "un-revoke" operation. If a manifest was revoked in error, the issuer must re-issue a new manifest with a new `manifest_id`. This is intentional: revocation records are evidence, not mutable state.
- Verifiers that cache the CRL must define a TTL. The spec recommends a maximum of 5 minutes for production deployments. A stale CRL is a security risk.
- The JSON-Lines file grows without bound. Operators running long-lived deployments need a compaction strategy: periodically emit a new CRL containing only records whose `manifest_id` corresponds to a non-expired manifest. The compacted file is still append-only from that point forward.

## References

- [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) — Well-Known URIs
- [W3C Status List 2021](https://www.w3.org/TR/vc-status-list/)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 Certificate Revocation Lists
- ADR-0001: RFC 8785 canonical JSON (used for the revocation record signing pre-image)
- Spec Section 3.7: Revocation record schema and discovery endpoint specification
