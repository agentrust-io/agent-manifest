# ADR-0002: Ed25519 as the standard cryptographic profile

**Status**: Accepted  
**Date**: 2026-05-01  
**Spec section**: Section 4.1

## Context

The manifest signature scheme must be chosen for the standard profile (Level 0–2). The choice affects implementation complexity, key sizes, signature sizes, and library availability across Python, TypeScript, Go, and .NET.

## Decision

Ed25519 (RFC 8032, cofactorless verification) is the standard profile signature algorithm. SHA-256 is the hash algorithm. The pre-image is the RFC 8785 canonical JSON of the manifest with the `signature` field excluded.

## Rationale

- Ed25519 is available in the standard library or a single dependency in all target languages (Python `cryptography`, Node.js `@noble/ed25519`, Go `crypto/ed25519`, .NET `System.Security.Cryptography`)
- Cofactorless verification (as specified in RFC 8032 §5.1.7) is used — this is the dominant implementation behavior and is required for cross-implementation compatibility
- 64-byte signatures and 32-byte keys are compact relative to RSA and ECDSA
- No patent encumbrances
- Widely deployed in TLS, SSH, and existing PKI infrastructure

## Alternatives considered

**ECDSA P-256**: Broader hardware support (more HSMs implement P-256 than Ed25519). Rejected because it requires a secure random nonce per signature (deterministic signing via RFC 6979 is possible but complex), and Ed25519 is deterministic by design.

**RSA-PSS**: Universally supported. Rejected because 2048-bit keys (4096-bit for future-proofing) are large, signatures are large, and RSA is slower than elliptic curve schemes.

**ML-DSA-65 as default**: The post-quantum algorithm. Rejected as the default because `pyoqs` (liboqs Python bindings) is not yet universally available and would increase the mandatory dependency footprint. ML-DSA-65 is available as the `[pq]` optional extra.

## Consequences

- Implementations must use cofactorless Ed25519 verification. Implementations that use cofactored verification (some older libraries) will fail conformance test AM-CRYPTO-003.
- The hybrid profile (standard + post-quantum simultaneously) is defined in Section 4.3. When hybrid mode is used, both Ed25519 and ML-DSA-65 signatures must be present and both must verify.
- Key IDs are the SHA-256 hash of the DER-encoded public key. This allows key rotation without key confusion.

## References

- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
