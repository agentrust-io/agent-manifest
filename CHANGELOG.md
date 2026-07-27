# Changelog

All notable changes to Agent Manifest are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Spec changes are marked **[SPEC]**; SDK changes are marked **[SDK]**.

## [Unreleased]

### Fixed

**[SDK]** A `signature` block with no `algorithm` field no longer falls back to Ed25519. The field is REQUIRED by spec 3.6 but sits outside the signing pre-image, and the verifier defaulted a missing identifier to the classical algorithm; it is now a `signature.algorithm` mismatch. Completes the 0.6.0 downgrade check, which only covered a present-but-weaker identifier.

### Documentation

**[SPEC]** New **ADR-0011: the manifest is a signed document, not a JWT/JOSE profile** (status: Proposed). Answers the recurring "why not just a JWT extension?" question on precedent rather than on capability, steelmanning EAT ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)) rather than dismissing it, and setting against it the choice every comparable multi-artifact provenance standard made: SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html)) mandates COSE_Sign1, DSSE rejected a JWS profile in writing, C2PA signs with `COSE_Sign1_Tagged`. The ADR also records a decision this project had never actually made: the envelope is neither JOSE nor COSE but a bespoke canonical-JSON detached signature. Migrating to COSE_Sign1 is recommended; Section 3.6 is unchanged until that is signed off.

**[SPEC]** Corrected three factual errors in the spec. Section 2.2 and Section 5 described the manifest signature as "JWS", which it has never been (there is no JOSE dependency in the SDK; the signature is a detached Ed25519 or ML-DSA-65 signature over an RFC 8785 pre-image). Section 10.4 cited EAT as RFC 9528, which is EDHOC; EAT is RFC 9711.

**[SPEC]** Section 3.6 gained a normative algorithm-binding rule making the 0.6.0 verifier behaviour part of the specification: because the `signature` block sits outside the pre-image, a verifier MUST cross-check the declared algorithm against the signed `crypto_profile`, MUST reject a downgrade, and MUST reject an unrecognized algorithm identifier rather than defaulting to Ed25519. Section 10.4 adds rows for RFC 9711 and RFC 9943 positioning Agent Manifest as the agent-layer profile of the SCITT model.

**[SDK]** `docs/index.md` FAQ answers "why not specify it as a JWT or JOSE profile?" with the short form of the ADR-0011 argument.

## [0.6.0] — 2026-07-26

Fixes the CLI that every document described but that nobody could run, and closes a signature-downgrade gap in the verifier.

### Fixed

**[SDK]** **The documented CLI invocation now works.** Every command was nested under a redundant second `manifest` group, so the real invocation was `manifest manifest verify signed.json` while the README, the docs site, the PyPI description, and the CLI's own module docstring all printed `manifest verify signed.json`. Running the published quickstart failed at the first step with `Error: No such command 'keygen'`. `tests/test_cli.py` used the nested form, so CI never caught it. Commands are now attached to the top-level group as documented; the nested spelling still works, is hidden from `--help`, and prints a deprecation warning (removal in 1.0). `test_documented_commands_are_top_level` guards the surface.

**[SDK]** `verify_manifest()` now cross-checks the signed `crypto_profile` against `signature.algorithm` and fails closed on a downgrade (spec 4.2). `crypto_profile` is inside the signing pre-image, but the whole `signature` block is excluded from it (spec 3.6), so the algorithm identifier could previously be rewritten without disturbing the signed bytes: a manifest declaring the post-quantum profile verified `VALID` on a classical-only Ed25519 signature. The check runs independently of `trusted_keys` (the downgrade is a property of the manifest, not of the verifier's key material) and is one-directional: it rejects a signature weaker than the declared profile requires and permits a stronger one, so an issuer dual-signing ahead of the profile flip is not flagged. New conformance vector `AM-VEC-020`.

### Documentation

**[SDK]** `docs/getting-started.md`: new "Watch it catch a change" step. Shows the two ways verification fails and how they differ — an edit to the signed record (signature fails, `signature_verified: false`) versus runtime drift against an intact signature (declared-vs-actual binding fails, `system_prompt: MISMATCH`) — and names the boot-time boundary, pointing at `attest_runtime_state()` for freshness. All printed values are copied from real runs.

**[SDK]** `docs/api-reference/cli.md` is now generated from the CLI by `scripts/gen_cli_reference.py` instead of hand-written. The hand-written page had drifted into fiction: it documented `manifest keygen --out/--print-pub`, `manifest verify --revocation-url/--min-slsa-level`, `manifest create --agent-id/--issuer/--model/--ttl-hours`, and `manifest revoke --crl-file/--key-file`, none of which exist, while omitting the options that do. `test_cli_reference.py` fails if the committed page drifts from the CLI again.

**[SDK]** CLI help output is readable: `\b` markers keep the example blocks from being rewrapped into one line, and `-o/--output`, `--enforce-hitl`, and `--enforce-attestation` have help text instead of appearing bare.

**[SDK]** Corrected CLI examples that could not have worked: `docs/operations/key-rotation.md` used the non-existent `manifest keygen --out ... --print-pub`, and `docs/index.md` plus `python/README.md` printed `manifest verify` without `--public-key`, which fails closed as `UNVERIFIABLE` and exits 1 rather than the `VALID` shown.

**[SDK]** `LIMITATIONS.md`: document that **Azure TDX is not supported for offline attestation** (hardware-confirmed). Azure runs TDX behind the Hyper-V paravisor, so the guest gets no signed DCAP quote — only a MAC'd `TDREPORT` via the vTPM — and rooting that as genuine silicon needs a networked service (Azure MAA). Offline TDX attestation is supported on non-paravisor guests (e.g. GCP C3); on Azure use SEV-SNP (`AzureCVMProvider`). Azure-MAA TDX support is tracked as a follow-up.

## [0.5.0] — 2026-07-21

Generalizes the verification API so cmcp and ca2a can delegate their full SNP/TDX/TPM crypto to this package (via PyPI) without changing behavior or rewriting their test fixtures. Backward compatible — all existing functions and signatures are unchanged.

### Added

**[SDK]** Generic, algorithm-agnostic certificate-chain verifier `verify_cert_chain(chain, trusted_roots, *, root_fingerprint_hash=SHA256)` (exported, with `CertChainError`). Verifies a leaf-first chain by honoring **each certificate's own** signature algorithm — ECDSA, RSASSA-PSS, or RSA PKCS#1 v1.5 — via `x509.Certificate.verify_directly_issued_by`, then pins the chain root by fingerprint. This is the shared primitive behind AMD VCEK, Intel PCK, and TPM AK chains; it lets both consumers replace their own chain verifiers (cmcp's synthetic RSA-PKCS1v15 ARK/ASK and ca2a's EC chains both verify through it). The AMD-specialized `verify_vcek_chain` is unchanged (kept as its hardware-validated specialization).

### Changed

**[SDK]** `parse_tdx_quote(quote, *, strict=True)` gained a `strict` flag. `strict=True` (default) keeps enforcing the production layout (`version==4`, `tee_type==0x81`); `strict=False` parses the header/body of an otherwise well-formed quote whose version/tee_type differ (e.g. consumers' synthetic vectors) without asserting production TDX identity. `verify_tdx_quote` is unaffected and always strict.

## [0.4.0] — 2026-07-21

Makes agent-manifest the canonical hardware-verification library for the org: SEV-SNP, TDX, and now TPM quote verification live here and are consumed by cmcp and ca2a via this PyPI package rather than duplicated per repo.

### Added

**[SDK]** Shared TPM 2.0 quote verifier (`agent_manifest._tpm_verify`, exported: `parse_tpm_quote`, `verify_tpm_quote`, `TpmQuote`, `TpmVerificationError`). Fail-closed appraisal of a `TPMS_ATTEST` quote: magic/type structural check, AK certificate chain to a caller-pinned trusted root, AK signature (ECDSA-P256 or RSA PKCS#1 v1.5 / SHA-256) over the attest blob, and constant-time qualifying-data (nonce) + PCR-digest binding checks. Wired into `verify_attestation_chain` (dispatch on `platform in {"tpm","aws-nitro"}`). Ported from ca2a's reference implementation so the three repos share one verifier. Caveat: exercised against synthetic self-consistent vectors; unlike the SEV-SNP/TDX paths it is not yet validated against a real TPM quote (follow-up).

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
