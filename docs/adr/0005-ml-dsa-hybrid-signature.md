# ADR-0005: ML-DSA-65 and hybrid Ed25519+ML-DSA-65 signature support

**Status**: Accepted  
**Date**: 2026-06-07  
**Spec section**: Section 2.4 (Cryptographic Profiles), Section 4.2 (Signature Algorithms)

## Context

NIST finalized ML-DSA (CRYSTALS-Dilithium) as FIPS 204 in August 2024, making it the primary post-quantum digital signature standard. Agents operating in regulated environments (FedRAMP High, EU AI Act high-risk systems) will face requirements to use quantum-resistant cryptography within the next 2–5 years.

The spec must answer: when and how does post-quantum cryptography enter the agent manifest?

Two decisions are intertwined:

1. Which ML-DSA parameter set to standardize on (ML-DSA-44, ML-DSA-65, or ML-DSA-87)
2. Whether to support hybrid mode — signing with both Ed25519 and ML-DSA-65 in a single manifest, requiring both to verify

ADR-0002 established Ed25519 as the standard profile. This ADR extends that decision to cover the post-quantum and hybrid profiles.

## Decision

**Parameter set**: Use **ML-DSA-65** (NIST Security Level 3, FIPS 204).

**Hybrid mode**: Support `Ed25519+ML-DSA-65` as an explicit `crypto_profile` value. A hybrid manifest carries both signature types; verifiers must validate both signatures independently. A verifier that does not support ML-DSA-65 must reject a hybrid manifest with `INCOMPATIBLE_VERSION`, not silently pass on the Ed25519 signature alone.

Three `CryptoProfile` values are defined:

- `standard` — Ed25519 only (Level 0/1 default)
- `post_quantum` — ML-DSA-65 only (required when classical crypto is prohibited by policy)
- `hybrid` — Ed25519 + ML-DSA-65 (recommended transition path for Level 2+)

PQC is required at conformance Level 2 and above. Level 0 and Level 1 deployments may use `standard` (classical only).

## Rationale

### ML-DSA-65 over ML-DSA-44

ML-DSA-44 targets NIST Security Level 2 with 2420-byte signatures. ML-DSA-65 targets NIST Security Level 3 with 3309-byte signatures. The 889-byte difference is trivial for a manifest that is signed once and cached. NIST recommends ML-DSA-65 for long-term protection; ML-DSA-44 would likely require a second migration within 10 years as cryptanalysis matures.

### ML-DSA-65 over ML-DSA-87

ML-DSA-87 targets NIST Security Level 5 but produces 4627-byte signatures. The additional security margin over Level 3 is not justified by any current threat model, and the signature size creates complications for manifests embedded in HTTP headers. ML-DSA-65 is the right balance between security margin and operational cost.

### Hybrid mode as the transition path

Mandating ML-DSA-65 alone immediately would break every existing verifier that has not yet integrated `liboqs`. The hybrid profile lets adopters commit to PQC today while remaining interoperable with classical infrastructure during the migration window (estimated 2–5 years). A classical verifier that holds the Ed25519 public key can still verify the Ed25519 signature. Once the ecosystem completes PQC migration, deployments can move to `post_quantum` only.

The requirement that both signatures must verify in hybrid mode prevents downgrade attacks: a hybrid manifest cannot be verified by stripping the ML-DSA signature and presenting only the Ed25519 one to a PQC-capable verifier.

### Avoiding algorithm agility

The spec defines exactly three named profiles. Arbitrary algorithm negotiation between signer and verifier is not supported. Algorithm agility has historically produced downgrade attacks; constraining to three named profiles eliminates negotiation semantics entirely.

## Alternatives considered

**X-Wing (ML-KEM + X25519 hybrid)**: A hybrid KEM combining X25519 and ML-KEM-768. Rejected because ML-KEM is a key encapsulation mechanism, not a signature scheme — it serves a different purpose (key exchange) and does not address signature authenticity.

**SLH-DSA (SPHINCS+)**: Hash-based signatures with no algebraic structural assumptions. Rejected because SLH-DSA signatures range from 7 KB to 50 KB depending on the parameter set, which is prohibitively large for a manifest that may be attached to every RPC.

**Falcon-512**: NIST FIPS 206 lattice-based signature with compact output (~666 bytes). Rejected because Falcon's Gaussian sampler has a history of implementation-specific timing side channels, and `liboqs` Falcon support is less mature than ML-DSA. It may be added in a future ADR once maturity is established.

**Mandate ML-DSA-65 immediately**: Drop Ed25519 from all profiles. Rejected — the migration window must exist; breaking every existing Level 0/1 deployment is not acceptable.

## Consequences

- `crypto_profile: hybrid` or `post_quantum` requires `pip install "agent-manifest[pq]"`, which pulls in the `oqs` package (Python bindings for `liboqs`, a C library). Importing `oqs` is deferred until a PQC operation is actually needed — the package is not imported at module load time.
- A Level 0 verifier without `oqs` installed cannot verify a `post_quantum` or `hybrid` manifest. The verifier must raise `INCOMPATIBLE_VERSION`. Silent pass is not permitted.
- Signature sizes: Ed25519 = 64 bytes, ML-DSA-65 = 3309 bytes, hybrid = 3373 bytes plus encoding overhead. Manifests passed in HTTP headers must use the `X-Agent-Manifest-Id` header (a UUID reference) rather than embedding the full signed manifest inline.
- The conformance test suite includes AM-CRYPTO-010 through AM-CRYPTO-020 covering all three profiles and hybrid verification rejection on partial signature sets.

## References

- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [liboqs — Open Quantum Safe](https://openquantumsafe.org/)
- [CISA Post-Quantum Cryptography Initiative](https://www.cisa.gov/quantum)
- ADR-0002: Ed25519 as the standard cryptographic profile
- Spec Section 4.2: Signature algorithm identifiers and profile definitions
