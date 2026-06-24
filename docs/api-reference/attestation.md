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

## Level 3  -  OPAQUE

::: agent_manifest._hw_providers.OPAQUEProvider

## Auto-provider

::: agent_manifest._auto_provider.select_provider

::: agent_manifest._auto_provider.SoftwareProvider
