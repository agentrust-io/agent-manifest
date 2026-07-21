# Attestation providers

Hardware attestation providers for Levels 1–3. See [Tutorial: Hardware attestation](../tutorials/hardware-attestation.md) for usage and mocking patterns.

> **Scope:** `extend_manifest_hash()` + `get_attestation_report()` run once at
> agent startup and prove which manifest was active when the TEE was initialised.
> They do not continuously monitor runtime state. For periodic freshness proofs
> use `attest_runtime_state()` — see [RuntimeAttestationReport](#runtimeattestationreport).

## Base types

::: agent_manifest._providers.AttestationProvider

::: agent_manifest._providers.AttestationReport

::: agent_manifest._providers.RuntimeAttestationReport

::: agent_manifest._providers.AttestationUnavailableError

## Level 1  -  TPM

::: agent_manifest._providers.TPMProvider

## Level 2  -  SEV-SNP and TDX

::: agent_manifest._hw_providers.SEVSNPProvider

::: agent_manifest._hw_providers.TDXProvider

## Level 3  -  OPAQUE (not implemented)

!!! warning "Not implemented"
    OPAQUE managed runtime attestation is **not implemented**. The managed
    service is not generally available, and the SDK does not verify the TRACE
    claim such a service would return (no claim-signature check, no
    `service_measurement` verification). `OPAQUEProvider` therefore fails closed
    at construction. Use a locally-verifiable provider (SEV-SNP / TDX / Azure
    CVM) for Level 1+ attestation. Tracked with issue #201 (§5).

::: agent_manifest._hw_providers.OPAQUEProvider

## Auto-provider

::: agent_manifest._auto_provider.select_provider

::: agent_manifest._auto_provider.SoftwareProvider
