# Changelog

All notable changes to Agent Manifest are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Spec changes are marked **[SPEC]**; SDK changes are marked **[SDK]**.

## [Unreleased]

### Added

**[SDK]** Intel TDX DCAP quote verification (`agent_manifest._tdx_verify`, exported), **hardware-validated on a non-paravisor TDX guest (GCP C3)**. `TDXProvider` now uses the configfs-TSM `tdx_guest` provider, which returns a full remotely-verifiable DCAP quote (v4, ECDSA-P256) instead of a bare local `TDREPORT`. Verification checks the quote's attestation-key signature over the TD report, the QE report binding, the PCK signature over the QE report, and the PCK certificate chain up to the **pinned Intel SGX Root CA** (embedded; offline). Wired into `verify_attestation_chain`, which now returns `passed=True` for a TDX report only when the quote + PCK chain verify. Closes the TDX half of the "shipped the binding without verification" gap (#204/#228); the previous `/dev/tdx-guest` ioctl path (raw TDREPORT, no signature check, RTMR-extend that never happened) has been removed. Azure TDX (paravisor/vTPM-rooted) remains a follow-up.
**[SDK]** `AzureCVMProvider` — hardware-attested manifest binding on Azure confidential VMs, validated on live SEV-SNP silicon (Azure DCasv5). Azure runs SNP behind a Hyper-V paravisor, so there is no `/dev/sev-guest`; the SNP report is read from the vTPM NV index `0x01400001` and the manifest hash is bound through the vTPM (PCR + AK-signed quote), with the AK rooted in silicon by the SNP report + VCEK chain. Auto-selected by `provider='auto'` on Azure.
**[SDK]** AMD SEV-SNP signature backend (`agent_manifest._snp_verify`, exported): SNP report parsing, HCL-report splitting, the Azure `REPORT_DATA == sha256(runtime_data)` binding check, ECDSA-P384 report-signature verification against the VCEK, and VCEK ← ASK ← ARK chain verification (with optional pinned AMD root). Validated against a real SEV-SNP report.
**[SDK]** `verify_attestation_chain` now performs real hardware-signature verification when VCEK/certificate material is supplied (previously always `NOT_IMPLEMENTED`); it returns `passed=True` only once the SNP signature and VCEK chain verify. Without VCEK material it still fails closed.

### Changed

**[SDK]** `SEVSNPProvider` now uses the kernel configfs-TSM interface (`/sys/kernel/config/tsm/report`, kernel 6.7+) for bare-metal / non-paravisor SNP guests; the previous `/dev/sev-guest` ioctl path (never hardware-validated, incorrect ABI) has been removed. **Hardware-validated on a non-paravisor SEV-SNP guest (GCP N2D, AMD Milan):** the manifest digest lands in the guest-controlled `REPORT_DATA` and the report verifies against the AMD VCEK chain. On Azure use `AzureCVMProvider`.
**[SDK]** Attestation providers (`AzureCVMProvider`, `SEVSNPProvider`, `TDXProvider`, `OPAQUEProvider`, `TPMProvider`) and the chain verifier are now exported from `agent_manifest`; CLI `manifest attest` accepts `--provider azure-cvm`.
**[SDK]** `OPAQUEProvider` is now explicitly **not implemented** and fails closed at construction. The OPAQUE managed attestation service is not generally available and the SDK never verified the TRACE claim it would return (no claim-signature or `service_measurement` check — issue #201 §5); shipping a path that looked verified but was not is worse than none. Use a locally-verifiable provider (SEV-SNP / TDX / Azure CVM) for Level 1+. The prior unverified HTTP flow has been removed.

## [0.3.0] — 2026-07-15

### Security

**[SDK]** Verification can now bind trusted signing keys to authorized issuers. `VerificationContext.trusted_key_issuers` maps each trusted `key_id` to the issuer SPIFFE URIs allowed to sign with it; when supplied, a manifest whose signing key is not authorized for its declared `issuer` is rejected (fail-closed). Opt-in and backward compatible: an empty map preserves prior behavior.

### Added

**[SDK]** Delegation verification is now part of the public API: `verify_delegation_chain`, `verify_hitl_approval`, `delegation_depth_exceeded`, `DelegationHopSigner`, and `HitlApprovalSigner` are exported from `agent_manifest`. Downstream projects (for example agentrust-io/cA2A) call `verify_delegation_chain` to verify an inbound peer's delegation chain, so the two implementations stay aligned rather than duplicated. No behavior change; these were previously reachable only through the private `_delegation` module.

## [0.2.0] — 2026-06-30

### Security

**[SDK]** Delegation chain root is now bound to the manifest issuer/agent identity — forged-authority chains are rejected.
**[SDK]** Scope-narrowing enforces constraint-superset, non-increasing `ttl_seconds`, and non-increasing `max_delegation_depth`.
**[SDK]** Verification schema-validates the manifest (fail-closed); CLI `verify` no longer prints bare `VALID` when artifact bindings were not checked.

### Changed

**[SPEC]** SNP/TDX attestation field corrections and provider experimental markers (`REPORT_DATA` at `0x50`); threat-model/levels documentation scoped to what TEE attestation provides.

### Fixed

**[SDK]** `PrincipalType` set reconciled (no `service`).

### Added

**[SPEC]** Memory Checkpoint & Delta Protocol (Section 3.2.6.2) — v0.2 incremental memory binding.
- Append-only operation-log (merkle-log) model lets persistent memory evolve across a session and prove the evolution was governed, without re-approving the whole store.
- Per-representation leaf canonicalization: key-value, semantic/vector (binds embedding + model id), and graph-RAG (nodes + edges).
- A governed checkpoint advance is accepted only with a valid RFC 9162 §2.1.2 consistency proof; an unproven change still triggers v0.1 drift detection (`MEMORY_DRIFT_DETECTED`) — fail-closed preserved.

**[SDK]** `MerkleTree.consistency_proof` + `verify_consistency` (RFC 9162 §2.1.2) in `agent_manifest._merkle`.
**[SDK]** `agent_manifest._memory_delta`: `build_memory_tree`, `MemoryCheckpoint`, `verify_delta`, `fold_kv`.
**[SDK]** `MemoryCheckpointBinding` model (`memory_root` anchor; additive — `MemoryBaselineBinding` and `snapshot_hash` semantics unchanged).

**[SDK]** Export the verification API from the package root, so relying parties
and gateways call `agent_manifest.verify_manifest()` and `VerificationContext`
directly instead of importing the private `_verify` module (#176).

**[SPEC]** Document runtime-session binding guidance for gateways, including
the signed fields that bind `agent_id`, artifact hashes, validity windows,
delegation handling, and attestation separation (#177).

## [0.1.0] — 2026-06-23

Stable launch release at Confidential Computing Summit, June 23 2026.

### Fixed

**[SDK]** Enforce `poisoning_scan.result` rules in verifier — bad scan results now correctly fail closed (#167).
**[SDK]** Align Pydantic models, examples, and signing logic to the v0.1 spec (#165).
**[SDK]** Transparency log and signing error paths fully covered; fail-closed verifier restored (#168).

## [0.1.0-alpha1] — 2026-06-04

Initial developer preview. Launching at Confidential Computing Summit, June 23 2026.

### Added

**[SPEC]** v0.1 specification published.
- All 10 artifact bindings defined (Sections 3.2.1–3.2.8, 3.4, 3.5)
- Hardware attestation binding for TPM, SEV-SNP, TDX, OPAQUE (Section 3.3)
- A2A delegation chain with Cedar scope constraint evaluation (Section 3.4)
- HITL approval records with hardware-signed approver identity (Section 3.5)
- Manifest signature protocol: Ed25519 / ML-DSA-65 / hybrid (Section 3.6)
- Revocation and key rotation protocols (Sections 3.7, 3.8)
- Standard and post-quantum cryptographic profiles (Section 4)
- Verification endpoint specification with error schema (Section 5)
- Integration architecture for AGT, cMCP, MCP (Section 6)
- Threat model covering 10 threat classes (Section 7)
- Conformance levels 0–3 with 197 conformance tests across 5 modules (Section 8)
- Regulatory mapping: EU AI Act, DORA, GDPR, HIPAA, PCI-DSS, FedRAMP (Section 9)

**[SDK]** Python SDK v0.1.0-alpha1 (`pip install agent-manifest`).
- `Manifest`, `ArtifactBindings`, and all 10 artifact binding Pydantic models
- `generate_ed25519`, `Ed25519Signer` for standard-profile signing
- `verify_manifest`, `VerificationContext`, `RevocationStore` for verification
- Merkle tree computation for RAG corpus and tool manifest catalog hash
- RFC 8785 canonical JSON serialization
- Hardware provider auto-selection: OPAQUE > SEV-SNP > TDX > TPM > software
- CLI: `manifest keygen`, `create`, `sign`, `attest`, `verify`, `revoke`
- Post-quantum support via `pyoqs`: `pip install "agent-manifest[pq]"`
- Verification server: `pip install "agent-manifest[server]"`
- Python 3.11, 3.12, 3.13 support
