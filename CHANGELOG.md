# Changelog

All notable changes to Agent Manifest are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Spec changes are marked **[SPEC]**; SDK changes are marked **[SDK]**.

## [Unreleased]

## [0.8.0] — 2026-08-01

Shares the `TPMT_SIGNATURE` parse and teaches the quote parser both attest framings, so cmcp and ca2a can delete their copies rather than keep three implementations of the same wire formats in step by hand. Phase A1 of consolidating TEE verification into this package. No change to manifest signing or verification behaviour.

### Added

**[SDK]** **`parse_tpmt_signature()` and `ParsedSignature` are now public**, so cmcp and ca2a can stop carrying a copy each. Both had byte-identical implementations of the `TPMT_SIGNATURE` unwrap that `tpm2_quote -s` and `tpm2-pytss`'s `signature.marshal()` produce, differing only in which exception they raised; cmcp's comment already named this as "the piece agent-manifest does not model". It raises `TpmVerificationError` rather than `ValueError`, so a downstream migrating off its own copy needs to widen its `except` clause. `struct.error` on a truncated buffer is now caught and re-raised as `TpmVerificationError`, which ca2a handled and cmcp did not.

**[SDK]** **`parse_tpm_quote()` accepts a size-prefixed `TPM2B_ATTEST` as well as a bare `TPMS_ATTEST`.** `tpm2_quote -m` writes the bare form and other producers write the wrapped one, so a verifier that accepts only one rejects genuine quotes from standard tooling. `TpmQuote.raw` is now always the inner `TPMS_ATTEST`, and `verify_tpm_quote()` checks the AK signature over that rather than over its argument — verifying over the outer bytes would have failed a real wrapped quote. For bare input, which is everything the suite previously exercised, both are the same bytes and behaviour is unchanged.

Framing is decided by requiring the magic to appear under one reading or the other, not by the leading bytes alone. The obvious implementation, "magic at offset 0 means bare, otherwise treat the first two bytes as a length", silently reinterprets a blob with a corrupt magic as a framing fault and reports `TPM2B_ATTEST size field invalid`, which sends whoever is debugging a one-bit corruption to the wrong problem. Two tests caught this and both are kept as regression guards.

### Changed

**[SPEC]** **Target standards body retargeted from AAIF to CoSAI Working Stream 4**, an OASIS Open Project, following the Phase 1 RFC in [cosai-oasis/ws4-secure-design-agentic-systems#149](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149). Affects the spec header, section 3.1 (who assigns the canonical `@context` URL), section 3.2.5 (scanner registry), section 10.1 through 10.3, and the governance set: `CHARTER.md`, `GOVERNANCE.md`, `MAINTAINERS.md`, `ANTITRUST.md`, `CONTRIBUTING.md`, `ROADMAP.md`, `README.md`. No normative data-model, cryptographic, or conformance change; nothing about how a manifest is signed or verified moves.

Three things did not change mechanically with the rest. The conformance test suite in section 8.2 was described as shipping "alongside the AGT donation to AAIF" and is now decoupled, because AGT's standards destination is governed separately and is not set by this charter. Two AAIF references are retained deliberately: the `AAIF Spec Enhancement Proposal (SEP)` route in section 6.3 and the `MCP (Anthropic / AAIF)` row in section 10.4 both describe MCP's own governance home, not this specification's target. And the IP terms are stated as consequences rather than commitments: the OASIS Open Projects IPR Policy requires a CLA plus a patent non-assert on non-trivial contributions, which is stricter than the DCO-only regime in force today, so `CHARTER.md` section 4 records that it takes effect only on WS4 acceptance and that the founding maintainer's terms under it need counsel sign-off first. Trademark transfer terms are marked to be determined rather than asserted.

### Fixed

**[SDK]** `parse_tdx_quote_signature()` now rejects a quote whose declared lengths overrun the buffer instead of silently parsing a shorter value. Four lengths come from the quote, which is untrusted input: the signature-data size, `cert_size`, `qe_auth_size`, and `pck_size`. Python slicing clamps rather than overreading, so an inflated length previously yielded a short slice and parsing continued against whatever fit. No read was ever out of bounds and the downstream signature check would fail, so this is fail-closed hardening rather than a memory-safety fix, but a verifier should reject a quote that declares 400 bytes and supplies 300 rather than appraise the 300. Found while reviewing the same parse in cmcp#420, which shares the derivation.

## [0.7.0] — 2026-07-27

Shares the hardware-validated TDX quote-signature parse so the sibling repos can stop carrying their own copies of the offsets, and specifies the v0.2 COSE envelope. No change to manifest signing or verification behaviour.

### Added

**[SPEC]** **COSE envelope specified for manifest version 0.2**: [`spec/agent-manifest-cose-envelope-v0.2.md`](spec/agent-manifest-cose-envelope-v0.2.md), phase 1 of the ADR-0011 migration ([#243](https://github.com/agentrust-io/agent-manifest/issues/243)). `COSE_Sign1` (tag 18), or `COSE_Sign` (tag 98) with two signers for a hybrid Ed25519 + ML-DSA-65 signature so that both entries covering one payload is structural rather than an application rule. Protected header carries `alg` (`-8` / `-49`, RFC 9053 and RFC 9964), `kid`, `content type` (3), and `typ` (16, RFC 9596); the payload is the RFC 8785 canonical JSON of the manifest, carried inline; the SCITT receipt attaches as `receipts` (unprotected label 394, RFC 9942 receipts). Media types `application/agent-manifest+json` (payload) and `application/agent-manifest+cose` (object), standards-tree, registration pending.

Three v0.1 mechanisms are deleted rather than ported, because each existed only to work around JSON having no defined place for post-signing data: the fixed `signed_fields` list and its coverage table, the `hitl_record.approvals` normalization rule, and the `transparency_log_entry` ordering rule. In v0.2 the payload is what is signed, and approvals, the attestation report, and the receipt all attach in the unprotected header. Hardware attestation binds `sha256` of the payload bytes, so there is no longer a set of fields to exclude and keep in sync. No code changes; manifest version 0.1 is untouched and continues to verify under v0.1 section 3.6.

**[SDK]** `parse_tdx_quote_signature()` and `TdxQuoteSignature` expose the validated DCAP v4 signature-section parse (de-nested QE report, QE signature, auth data, PCK chain PEM) so sibling repos can delegate to it instead of reimplementing the offsets. Real quotes nest the QE material under a type-6 `QE_REPORT_CERTIFICATION_DATA` header; a flat parse reads the QE report six bytes early and rejects every genuine quote, which is what happened in cmcp and ca2a. `verify_tdx_quote()` now calls the shared parse, so there is one copy of the layout, and two regression tests pin the nested structure.

## [0.6.1] — 2026-07-27

Closes a crash in `verify_manifest()` reachable from untrusted input on a default install, and settles the signature-envelope question for v0.2. No change to how manifests are signed or to any existing verification result.

### Fixed

**[SDK]** **`verify_manifest()` no longer raises on a post-quantum manifest when the `pq` extra is absent.** `pyoqs` is optional, so on a default install any manifest declaring `ML-DSA-65` or `hybrid-Ed25519-ML-DSA-65` reached `_require_oqs()` and crashed the engine with an uncaught `RuntimeError`. Since a manifest is untrusted input, a verification endpoint would answer 500 to an attacker-supplied manifest rather than returning a verdict. `_require_oqs()` now raises `AlgorithmUnavailableError` (a `RuntimeError` subclass, so existing callers are unaffected), the engine catches it, records the reason as a warning, and returns **`UNVERIFIABLE`**. Not `MISMATCH`: the verifier has established nothing about a manifest that may be entirely valid, so accusing it of a defect would be wrong. An algorithm identifier outside the registry remains a `MISMATCH`, rejected by the schema enum before verification runs.

**[SDK]** A `signature` block with no `algorithm` field no longer falls back to Ed25519. The field is REQUIRED by spec 3.6 but sits outside the signing pre-image, and the verifier defaulted a missing identifier to the classical algorithm; it is now a `signature.algorithm` mismatch. Completes the 0.6.0 downgrade check, which only covered a present-but-weaker identifier.

### Documentation

**[SPEC]** **ADR-0005 amended** after a spec-versus-implementation audit. Three of its statements did not match what shipped: it defined three `crypto_profile` values (`standard`, `post_quantum`, `hybrid`) where the spec and SDK define two (`standard`, `post-quantum`) with hybrid as a *signature algorithm* rather than a profile; it required the post-quantum profile at "Level 2 and above" where section 8.1 places it at Level 3; and it required an unsupported-algorithm verifier to "raise `INCOMPATIBLE_VERSION`", which is reserved for unsupported specification versions and is not something a verifier should raise at all. The original text is preserved per the ADR immutability rule, with an amendment section recording each correction. Section 4.2 now states the `UNVERIFIABLE` requirement normatively.

**[SPEC]** New **section 10.5, SCITT profile mapping**. Maps every structural piece of this specification to its RFC 9943 term (Artifact, Subject, Statement, Issuer, Signed Statement, Transparency Service, Receipt, Transparent Statement, Registration Policy, Auditor), which turns "agent-layer profile of SCITT" into a checkable claim and tells an implementer which parts are agent-specific (sections 3.2 to 3.5) and which are inherited. The section also states what the spec deliberately does not restate: OpenSSF Model Signing for the model artifact, SLSA and in-toto for build provenance, SCITT and Sigstore for transparency. Section 10.4 gains an OMS row, and v0.2 gains a line item for an explicit OMS bundle reference in `model_identity` so a verifier can follow the chain from agent to model publisher instead of trusting an operator-asserted hash.

**[SPEC]** New **[ADR-0011](docs/adr/0011-signature-envelope.md): the manifest is a signed document, not a JWT/JOSE profile**, accepted. Answers the recurring "why not just a JWT extension?" question on precedent rather than on capability, steelmanning EAT ([RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html)) rather than dismissing it, and setting against it the choice every comparable multi-artifact provenance standard made: SCITT ([RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html)) mandates COSE_Sign1, DSSE rejected a JWS profile in writing, C2PA signs with `COSE_Sign1_Tagged`. The ADR also records a decision this project had never actually made: the envelope is neither JOSE nor COSE but a bespoke canonical-JSON detached signature, which carries both properties DSSE cites as reasons to avoid JWS while lacking a specification anyone else implements.

The accepted decision is that **the envelope moves to COSE_Sign1 in spec v0.2**. The post-quantum profile is not a blocker, which was the main technical risk: [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964.html) (Standards Track, May 2026) gives ML-DSA final IANA code points in COSE (ML-DSA-65 = `alg` -49, AKP key type 7). Migration is sequenced in five phases and gated on the manifest `version` field, so v0.1 records keep verifying unchanged; tracked in [#243](https://github.com/agentrust-io/agent-manifest/issues/243). Hybrid is the one construction COSE has no single answer for and is deferred to the v0.2 spec work. Nothing in this release changes how a manifest is signed.

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
