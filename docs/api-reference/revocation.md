# Revocation

Revocation withdraws a manifest before it expires, for example after a key leak or when an agent is retired. These functions sign a revocation record, store records in a list that only grows, and serve that list over HTTP so verifiers can check it. See [ADR-0007](../adr/0007-revocation-json-lines-crl.md) for the format.

Certificate Revocation List (CRL) for agent manifests. See [Tutorial: Revocation and key rotation](../tutorials/revocation-and-key-rotation.md) for usage examples.

## Signing and verification

::: agent_manifest._revocation.sign_revocation

::: agent_manifest._revocation.verify_revocation_signature

## Record types

::: agent_manifest._revocation.SignedRevocationRecord

## CRL storage

::: agent_manifest._revocation.FileCRL

## FastAPI router

::: agent_manifest._revocation.create_crl_router
