# ADR-0005: ML-DSA-65 and hybrid Ed25519+ML-DSA-65 signature support

**Status**: Accepted  
**Date**: 2026-05-18  
**Spec section**: Section 2.4 (Cryptographic Profiles), Section 4.2 (Signature Algorithms)

## Context

NIST finalized ML-DSA (CRYSTALS-Dilithium) as FIPS 204 in August 2024, making it the primary post-quantum digital signature standard. Agents operating in regulated environments (FedRAMP High, EU AI Act high-risk systems) will face requirements to use quantum-resistant cryptography within the next 2–5 years.

The spec must answer: when and how does post-quantum cryptography enter the agent manifest?

Two separate decisions are intertwined:

1. **Which ML-DSA parameter set** to standardize on (ML-DSA-44, ML-DSA-65, or ML-DSA-87)
2. **Whether to support hybrid mode** (Ed25519 + ML-DSA-65 in a single signature block)

## Decision

**Parameter set**: Use **ML-DSA-65** (NIST Security Level 3, 128-bit quantum security).

**Hybrid mode**: Support `Ed25519+ML-DSA-65` as an explicit `crypto_profile` option. A hybrid manifest carries both signature types; verifiers must validate both. Single-algorithm manifests (Ed25519-only or ML-DSA-65-only) remain valid.

Three `CryptoProfile` values:
- `standard`  -  Ed25519 only (Level 0/1 default)
- `post_quantum`  -  ML-DSA-65 only (Level 2+ when classical crypto is prohibited)
- `hybrid`  -  Ed25519 + ML-DSA-65 (recommended transition path for Level 2+)

## Rationale

### ML-DSA-65 over ML-DSA-44

ML-DSA-44 provides 128-bit classical / ~2-qubit security. ML-DSA-65 provides 192-bit classical / ~3-qubit security. The 48-byte additional signature size (2420 → 3309 bytes) is a trivial cost for a manifest that is signed once and cached. NIST recommends ML-DSA-65 for long-term protection; choosing ML-DSA-44 would likely require a second migration within 10 years.

### ML-DSA-65 over ML-DSA-87

ML-DSA-87 provides 256-bit security but produces 4627-byte signatures. The additional cost over ML-DSA-65 is unjustified for current threat models. NIST reserves ML-DSA-87 for extreme scenarios; no known deployed system requires it today.

### Hybrid mode as the transition path

Mandating ML-DSA-65 immediately would break every existing verifier that has not yet integrated `liboqs`. The hybrid profile lets adopters make a commitment to PQC today while remaining interoperable with classical verifiers during the transition window (estimated 2–5 years). A classical verifier validates Ed25519 and ignores the ML-DSA-65 signature; a PQC-capable verifier validates both.

### Avoiding algorithm agility as a footgun

The spec does not support arbitrary algorithm combinations. Only the three profiles above are valid. Algorithm agility  -  allowing any signer to negotiate any algorithm with any verifier  -  has historically produced downgrade attacks. Constraining to three named profiles eliminates negotiation entirely.

## Alternatives considered

**Mandate ML-DSA-65 immediately, drop Ed25519**: Breaks backward compatibility with all existing Level 0/1 deployments. Rejected  -  the migration window must exist.

**Support SPHINCS+**: Hash-based signatures, no algebraic assumptions, conservative choice. Rejected because SPHINCS+ signatures are 7–50 KB depending on parameter set, which is prohibitively large for a manifest that may be attached to every HTTP request.

**Support Falcon-512 / Falcon-1024**: NIST FIPS 206 (Falcon). Lattice-based with smaller signatures than ML-DSA. Rejected for this ADR because `liboqs` Falcon support is less mature than ML-DSA, and Falcon's Gaussian sampling has a history of implementation-specific timing issues. Can be added in a future ADR.

**Algorithm negotiation**: Let the signer declare any algorithm and the verifier negotiate. Rejected  -  downgrade attacks, implementation complexity, and the spec would need to define negotiation semantics across all four SDKs.

## Consequences

- `crypto_profile: hybrid` or `post_quantum` requires `pip install "agent-manifest[pq]"` which pulls in `oqs` (Python bindings for `liboqs`). The `oqs` package is an optional dependency to avoid forcing a C library on all users.
- A Level 0 verifier without `oqs` installed cannot verify a `post_quantum` or `hybrid` manifest. The verifier raises `CryptoProfileNotSupported`  -  not a silent pass.
- Signatures grow from 64 bytes (Ed25519) to 3309 bytes (ML-DSA-65) or 3373 bytes (hybrid). Manifests passed in HTTP headers must use `X-Agent-Manifest-Id` (a UUID reference) instead of embedding the full signed manifest in the header.
- The conformance test suite includes AM-CRYPTO-010 through AM-CRYPTO-020 covering all three profiles and hybrid verification.

## References

- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [liboqs  -  Open Quantum Safe](https://openquantumsafe.org/)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- Spec Section 4.2: Signature algorithm identifiers
