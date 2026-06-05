# ADR-0007: Append-only JSON-Lines CRL for manifest revocation

**Status**: Accepted  
**Date**: 2026-05-22  
**Spec section**: Section 3.7 (Revocation)

## Context

A compromised agent — one whose signing key has leaked, whose behavior has been found malicious, or that has been decommissioned — must be stoppable without waiting for its manifest to expire naturally. The manifest format needs a revocation mechanism that:

1. Lets an authorised party revoke any manifest in under 60 seconds
2. Makes the revocation tamper-evident (the revocation record cannot be forged or deleted undetected)
3. Is queryable by a verifier without an expensive database join or X.509 infrastructure
4. Works for the SDK-hosted mode (developer running a local verifier) and a fleet mode (centralized CRL service)

## Decision

Use **append-only JSON-Lines** as the CRL file format. Each line is a JSON-encoded `SignedRevocationRecord` containing `{manifest_id, revoked_at, reason, revoked_by, revocation_signature, signer_key_id}`. The revocation record is signed by the **revoking authority's Ed25519 key** — not the original manifest issuer's key.

The standard discovery endpoint is `GET /.well-known/agent-manifest/revocation` (returns all records) and `GET /.well-known/agent-manifest/revocation/{manifest_id}` (returns one record or 404).

`FileCRL` is provided as the reference implementation for development and small deployments. Production deployments are expected to replace it with a database-backed store.

## Rationale

**JSON-Lines for append-only semantics.** Each revocation is one line, appended atomically. Reads parse line-by-line. There is no locking contention between writers and readers — the file grows monotonically and old entries are never modified. This makes the CRL file auditable: a git-committed CRL is an immutable audit trail.

**Signed revocation records prevent forgery.** Without a signature, an attacker who gains write access to the CRL file could add or remove entries. The signature over `{manifest_id, revoked_at, reason, revoked_by}` means tampering with any field invalidates the signature. The `signer_key_id` tells verifiers which public key to use for verification.

**Revoking authority is separate from manifest issuer.** This allows a security team to revoke manifests signed by a compromised issuer key — without holding the issuer key. The revoking authority's public key can be published out-of-band and rotated independently.

**Discovery endpoint follows `.well-known` convention.** RFC 8615 `.well-known` URIs are the established mechanism for service metadata discovery. Using `/.well-known/agent-manifest/revocation` means any HTTP client can locate the CRL without configuration.

## Alternatives considered

**W3C Status List 2021 (bitstring revocation list)**: A compact bitstring where each bit represents one credential. Rejected because it requires assigning a sequential integer index to each manifest at issuance time — a coordination requirement between the issuer and the CRL operator. It also introduces a dependency on the W3C Verifiable Credentials data model, which is not otherwise required by the spec.

**RFC 5280 X.509 CRL format**: DER-encoded binary format with ASN.1 structure. Rejected because the manifest ecosystem is JSON-native; requiring ASN.1 parsing in every SDK is a disproportionate dependency for a JSON-based standard.

**Database-only (no file format)**: Require production deployments to use a database and provide no file-backed reference implementation. Rejected because it makes the developer experience poor — a developer running `manifest verify` locally cannot easily stand up a Postgres instance to test revocation. `FileCRL` gives a working implementation with zero infrastructure.

**OCSP (Online Certificate Status Protocol)**: Per-certificate online status check. Rejected because it requires an always-available OCSP responder and creates a privacy leak (the OCSP responder learns which manifests are being verified). JSON-Lines CRL can be cached and served from a CDN.

## Consequences

- `FileCRL` is explicitly a development tool. The `create_crl_router()` docstring warns that production deployments should use a database-backed store. This distinction must be maintained in all documentation.
- The CRL is append-only by design. There is no "un-revoke" operation. If a manifest was revoked in error, the issuer must re-issue a new manifest with a new `manifest_id`. This is intentional: revocation records are evidence.
- Verifiers that cache the CRL must define a cache TTL. The spec recommends a maximum of 5 minutes for production deployments. A stale CRL is a security risk.
- The JSON-Lines format means the CRL file grows without bound. Operators running long-lived deployments need a compaction strategy: periodically emit a new CRL containing only records whose `manifest_id` still corresponds to a non-expired manifest.

## References

- [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) — Well-Known URIs
- [W3C Status List 2021](https://www.w3.org/TR/vc-status-list/)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 CRL
- Spec Section 3.7: Revocation record schema
