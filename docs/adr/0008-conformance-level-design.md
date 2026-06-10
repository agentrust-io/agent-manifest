# ADR-0008: Four conformance levels (0–3) rather than binary conformant/non-conformant

**Status**: Accepted  
**Date**: 2026-06-07  
**Spec section**: Section 6 (Conformance)

## Context

Different deployment environments offer materially different trust guarantees. A developer laptop, a production Linux server with TPM 2.0, an AMD SEV-SNP confidential VM, and a managed TEE with a full cryptographic audit chain are not equivalent. The spec needs to communicate these differences in a way that:

1. Allows adopters to start with a low-friction option and upgrade incrementally
2. Maps cleanly to specific regulatory requirements (EU AI Act risk tiers, FedRAMP impact levels, HIPAA, DORA)
3. Is unambiguous for both implementers and auditors
4. Scales with the cryptographic machinery available in a given environment

The alternative is a binary conformant/non-conformant model where every deployment meets the same bar or does not conform at all.

## Decision

Define **four conformance levels** numbered 0 through 3. Each level is a strict superset of the one below: a Level 2 implementation is also Level 1 and Level 0 conformant.

| Level | Name | Hardware requirement | Attestation |
|-------|------|---------------------|-------------|
| 0 | Software-only | None | Ed25519 signature; no hardware measurement |
| 1 | TPM-attested | TPM 2.0 | SHA-256 of manifest pre-image extended into a TPM PCR; PCR quote embedded in the manifest |
| 2 | Confidential compute | AMD SEV-SNP or Intel TDX | Manifest hash extended into HOST_DATA or RTMR; hardware-signed attestation report |
| 3 | Managed TEE + audit chain | OPAQUE runtime or equivalent | Silicon measurement plus hardware-signed Merkle-rooted audit chain |

The spec defines **197 conformance tests** distributed across levels. A conformance claim must specify the level: "this implementation is Level 2 conformant" is a meaningful and auditable statement. "This implementation is conformant" without a level qualifier is not.

## Rationale

**Four levels, not two, because the hardware landscape has four meaningful tiers.** A binary model forces a choice: set the bar at Level 0 (making conformance meaningless for regulated use cases) or at Level 2 (blocking developer machines, CI pipelines, and non-EU edge deployments). Neither option is usable. Trust is not binary.

**Level 0 is still valid and useful.** A software-signed manifest with no hardware attestation is cryptographically stronger than no manifest at all. It establishes agent identity, binds artifacts, supports delegation chains, and integrates with the revocation mechanism. Level 0 is appropriate for development environments, CI/CD pipelines, and non-regulated production deployments where identity binding is the primary goal. Excluding Level 0 would eliminate developer experience entirely and block the adoption path.

**Level 1 maps to universally available server hardware.** TPM 2.0 is standard on Azure, AWS, and GCP VM instances and on most modern Linux servers. It is deployable without proprietary infrastructure or cloud-provider-specific APIs. Level 1 provides hardware-rooted trust without requiring confidential compute.

**Level 2 covers regulated data workloads.** AMD SEV-SNP is available on Azure DCasv5, AWS C6a Nitro, and GCP N2D instances. Intel TDX is available on Azure DCedsv5 and GCP C3. Level 2 provides strong memory isolation and remote attestation, which satisfies EU AI Act Article 9 risk management requirements for high-risk AI systems.

**Level 3 covers the highest-assurance environments.** A Merkle-rooted audit chain inside a managed TEE provides non-repudiable, hardware-anchored evidence of every decision the agent made, tied to a silicon measurement. This evidence level is required for FedRAMP High, HIPAA covered components handling PHI, and financial regulation (DORA) critical function assessment.

**Strict superset semantics simplify testing.** A Level 2 test suite runs all Level 0 and Level 1 tests plus the Level 2-specific tests. There is no ambiguity about what "passes Level 2" means.

**197 tests covers the full combination space.** The test count reflects all field combinations across 4 levels multiplied by attestation provider variants, artifact binding field permutations, and crypto profile variants. The distribution is: Level 0: 89 tests, Level 1: 51 tests, Level 2: 42 tests, Level 3: 15 tests.

## Alternatives considered

**Binary conformant/non-conformant**: A single bar that all deployments must meet. Rejected because the bar cannot be set at a useful level  -  Level 0 makes conformance meaningless for regulated environments; Level 2 blocks widespread adoption by excluding developer machines and edge devices.

**Three tiers (dev/prod/regulated)**: Drop Level 1 (TPM-attested) and collapse TPM into the middle tier. Rejected because TPM attestation and SEV-SNP/TDX confidential compute are qualitatively different: TPM measures the boot chain but does not provide memory isolation. Treating them identically misstates the security properties and would mislead auditors.

**Five or more tiers**: Further subdivide Level 3 or add a Level 4. Rejected because the spec's hardware attestation providers do not currently offer a fifth meaningfully distinct tier. More tiers increase conformance test surface area without adding regulatory clarity.

**Named tiers instead of numbers (Bronze/Silver/Gold)**: Rejected because numbered levels compose naturally with version identifiers, can be referenced normatively ("Level 2 or above"), and resist marketing inflation. "Gold" is ambiguous across organizations; "Level 2" is not.

**Attestation as a boolean field**: A single `attested: true/false` instead of a level. Rejected because it collapses the distinction between TPM, SEV-SNP, and managed TEE  -  which matters for regulatory mapping and threat modeling.

## Consequences

- A verifier must validate the `attestation.level` field against its configured minimum accepted level. A verifier requiring Level 2 must reject Level 0 and Level 1 manifests  -  not silently accept them.
- PQC signatures (`crypto_profile: hybrid` or `post_quantum`) are required at Level 2 and above, as specified in ADR-0005.
- Regulatory mappings in `docs/compliance/` use conformance levels as the unit of comparison. Level 0 satisfies developer/test environments. Level 2 satisfies EU AI Act Article 9 risk management requirements for high-risk AI systems. Level 3 satisfies FedRAMP High, HIPAA covered entity requirements, and DORA critical function assessment.
- The `VerificationContext.enforce_attestation` flag gates Level 1+ at verification time. Future versions will add `min_attestation_level: int` for explicit minimum level enforcement in configuration.

## References

- [EU AI Act Article 14](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:52021PC0206)  -  Human oversight requirements for high-risk AI
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)  -  FedRAMP High control baseline
- [AMD SEV-SNP](https://www.amd.com/en/developer/sev.html)
- [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- ADR-0005: ML-DSA-65 hybrid signatures (PQC requirement at Level 2+)
- Spec Section 6: Conformance requirements and test identifier allocations
