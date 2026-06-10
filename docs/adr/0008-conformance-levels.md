# ADR-0008: Four conformance levels (0–3)

**Status**: Accepted  
**Date**: 2026-05-24  
**Spec section**: Section 6 (Conformance)

## Context

Different deployment environments offer radically different trust guarantees: a developer laptop, a production Linux server with TPM, an AMD SEV-SNP confidential VM, and a managed TEE with audit logging are not the same. The spec needs to communicate these differences in a way that:

1. Allows adopters to start with a low-friction option and upgrade incrementally
2. Maps to specific regulatory requirements (EU AI Act risk tiers, FedRAMP impact levels)
3. Is unambiguous for both implementers and auditors
4. Scales with the cryptographic machinery actually available

The alternative to a level system is a binary conformant/non-conformant model  -  every deployment must meet the same bar, or it does not conform.

## Decision

Define **four conformance levels** numbered 0 through 3. Each level is a strict superset of the one below: a Level 2 implementation is also Level 1 and Level 0 conformant.

| Level | Name | Hardware requirement | Attestation |
|-------|------|---------------------|-------------|
| 0 | Software-only | None | Ed25519 signature; no hardware measurement |
| 1 | TPM-attested | TPM 2.0 on Linux | SHA-256 of manifest pre-image extended into a TPM PCR; PCR quote in the manifest |
| 2 | Confidential compute | AMD SEV-SNP or Intel TDX | Manifest hash extended into HOST_DATA or RTMR; hardware-signed attestation report |
| 3 | Managed TEE + audit chain | OPAQUE runtime or equivalent | Silicon measurement plus hardware-signed audit chain with Merkle root |

The spec defines **197 conformance tests** distributed across levels. A conformance claim must specify the level: "this implementation is Level 2 conformant" is a meaningful statement; "this implementation is conformant" is not.

## Rationale

**Four levels, not two, because the hardware landscape has four meaningful tiers.** A binary model would either require all deployments to have TPM/SEV-SNP (blocking edge devices, developer machines, and non-EU deployments) or admit software-only manifests as indistinguishable from hardware-attested ones. Neither is acceptable.

**Level 0 is still useful.** A signed manifest with no hardware attestation is cryptographically stronger than no manifest at all. It establishes agent identity, binds artifacts, and supports delegation and revocation. Level 0 is appropriate for development environments, CI/CD, and non-regulated production deployments where identity binding is the primary goal.

**Levels 1–2 map to existing hardware programs.** TPM 2.0 is standard on Azure, AWS, and GCP VMs and on most modern Linux hardware. SEV-SNP is available on Azure DCasv5, AWS C6a Nitro, and GCP N2D instances today. Intel TDX is available on Azure DCedsv5 and GCP C3. Level 1 and Level 2 are deployable without proprietary infrastructure.

**Level 3 covers the highest-assurance use case.** A Merkle-rooted audit chain inside a managed TEE provides non-repudiable, hardware-anchored evidence of every decision the agent made. This is the evidence level required for FedRAMP High and EU AI Act very high-risk systems.

**Strict superset semantics simplify testing.** A Level 2 test suite runs all Level 0 and Level 1 tests plus the Level 2-specific tests. There is no ambiguity about what "passes Level 2" means: all 197 tests at that level and below.

## Alternatives considered

**Binary conformant/non-conformant**: All implementations must meet a single bar. Rejected because the bar would have to be set at Level 0 (lowest common denominator) or Level 2 (excluding TPM-only deployments). Neither is useful: a Level 0 bar makes conformance meaningless, a Level 2 bar blocks widespread adoption.

**Three levels (no Level 3)**: Drop the managed TEE tier. Rejected because FedRAMP High and equivalent frameworks require a higher-assurance option than hardware attestation alone. The audit chain root  -  a hardware-signed Merkle commitment to every agent decision  -  is qualitatively different from a TPM PCR extension.

**Named tiers instead of numbers (Bronze/Silver/Gold)**: Rejected because numbered levels compose naturally with version identifiers and are easier to reference in normative text. "Level 2" is unambiguous; "Gold" invites marketing inflation.

**Attestation as a boolean field**: A single `attested: true/false` field instead of a level. Rejected because it loses the distinction between TPM, SEV-SNP, and managed TEE  -  which matters for regulatory mapping and threat modeling.

## Consequences

- A verifier must validate the `attestation.level` field against its minimum accepted level. A verifier that requires Level 2 must reject Level 0 and Level 1 manifests  -  not silently accept them.
- The `VerificationContext.enforce_attestation` flag gates Level 1+ at verification time. Future versions will add `min_attestation_level: int` for finer control.
- Regulatory mappings published in `docs/compliance/` use conformance levels as the unit of comparison: "EU AI Act Article 14 requires Level 1 or above for high-risk AI systems."
- The 197 conformance tests are distributed as: Level 0: 89 tests, Level 1: 51 tests, Level 2: 42 tests, Level 3: 15 tests.

## References

- [EU AI Act Article 14](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206)  -  Human oversight requirements
- [NIST SP 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)  -  FedRAMP control baseline
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- Spec Section 6: Conformance requirements and test identifiers
