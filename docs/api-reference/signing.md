# Signing

These functions create signing keys, sign a manifest, and check a signature. Use them to issue manifests or to check one with a public key you already trust. Ed25519 is the default signature algorithm; ML-DSA-65 is a post-quantum algorithm, designed to resist future quantum computers, and is available as an optional extra.

Ed25519 and ML-DSA-65 (post-quantum) signing for agent manifests. See [ADR-0005](../adr/0005-ml-dsa-hybrid-signature.md) for the signature design.

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
