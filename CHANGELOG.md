# Changelog

All notable changes to Agent Manifest are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Spec changes are marked **[SPEC]**; SDK changes are marked **[SDK]**.

## [Unreleased]

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
