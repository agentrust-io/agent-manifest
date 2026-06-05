# Signing

Ed25519 and ML-DSA-65 (post-quantum) signing for agent manifests. See [ADR-0005](../adr/0005-ml-dsa-hybrid-signatures.md) for the signature design.

## Key generation

::: agent_manifest._signing.generate_ed25519

::: agent_manifest._signing.Ed25519KeyPair

## Signing

::: agent_manifest._signing.Ed25519Signer

## Verification

::: agent_manifest._signing.Ed25519Verifier

## Signing internals

::: agent_manifest._signing.signing_pre_image

::: agent_manifest._signing.SIGNED_FIELDS

## Canonicalisation

::: agent_manifest._canonicalize.canonicalize

::: agent_manifest._canonicalize.canonical_hash
