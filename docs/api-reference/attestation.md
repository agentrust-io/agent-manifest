# Attestation providers

Hardware attestation providers for Levels 1–3. See [Tutorial: Hardware attestation](../tutorials/hardware-attestation.md) for usage and mocking patterns.

## Base types

::: agent_manifest._providers.AttestationProvider

::: agent_manifest._providers.AttestationReport

::: agent_manifest._providers.AttestationUnavailableError

## Level 1 — TPM

::: agent_manifest._providers.TPMProvider

## Level 2 — SEV-SNP and TDX

::: agent_manifest._hw_providers.SEVSNPProvider

::: agent_manifest._hw_providers.TDXProvider

## Level 3 — OPAQUE

::: agent_manifest._hw_providers.OPAQUEProvider

## Auto-provider

::: agent_manifest._auto_provider.select_provider

::: agent_manifest._auto_provider.SoftwareProvider
