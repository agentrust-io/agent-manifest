# Roadmap

This page shows what Agent Manifest has shipped, what is still open, and what the project will not try to do. Status as of October 2026: the SDK is at 0.15.0 (2026-09-30) and the specification is at v0.2 draft. The [changelog](https://github.com/agentrust-io/agent-manifest/blob/main/CHANGELOG.md) is the record of what has actually shipped.

## Shipped: v0.1 developer preview (June 2026)

Launched at Confidential Computing Summit, June 23 2026.

- Specification: all 10 artifact bindings, conformance levels 0 to 3, and a 197-test conformance suite defined in section 8.2
- Python SDK: signing, verification, hardware attestation (TPM / SEV-SNP / TDX / OPAQUE), CLI
- Runtime attestation freshness proofs: `attest_runtime_state()` + `verify_runtime_report()` (spec §3.3.2, ADR-0010)
- Standard crypto profile: Ed25519, SHA-256, RFC 8785
- Post-quantum profile: ML-DSA-65 (NIST FIPS 204), SHAKE-256 (via `[pq]` extra)
- Integration architecture documented: AGT, cMCP, MCP

## Shipped since June

- **Intel TDX quote verification** (`agent_manifest._tdx_verify`), hardware-validated on a GCP C3 TDX guest, and **Azure confidential VM attestation** (`AzureCVMProvider`, vTPM-rooted SEV-SNP with the AMD certificate chain), validated on Azure DCasv5. Both in SDK 0.4.0 (2026-07-21). Azure TDX is not supported for offline attestation because Azure runs TDX behind a paravisor; see LIMITATIONS.
- **Target standards body moved to CoSAI Working Stream 4** after the Phase 1 RFC ([cosai-oasis/ws4-secure-design-agentic-systems#149](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/issues/149)), SDK 0.8.0 (2026-08-01).
- **Specification v0.2 draft** (August 2026): the `@context` URI moved to a controlled domain (ADR-0012) and the signature envelope moved to COSE_Sign1 ([envelope spec](spec/agent-manifest-cose-envelope-v0.2.md)).
- **Revocation endpoint**: `create_crl_router()` in `agent_manifest._revocation` serves a `FileCRL` over HTTP. `FileCRL` is a development store; production needs a database-backed store (ADR-0007).
- **HITL admissibility reporting** (`VerificationResult.hitl_admissibility`, issue #348), SDK 0.13.0 (2026-09-25).

## Open: candidates for the next specification revision

Driven by adopter feedback. Any normative change goes through the RFC process (14-day comment period).

- **HITL approval scheme clarification**: specify whether hybrid mode applies to approver signatures; document approver key rotation
- **Policy bundle test vector**: add a Merkle root test vector for composite bundles (Section 3.2.2)
- **RAG corpus poisoning precedence**: explicit rule for HITL override of `poisoning_scan.result: flagged`
- **Memory baseline TTL carve-out**: reconcile the artifact-only refresh exception with the immutability rule
- **Delegation non-Cedar fallback**: static scope narrowing for verifiers without Cedar support
- **Evidence pack format** for the verification server
- **TypeScript SDK**: community contribution welcome; see issue tracker for scope
- **MCP 2026 compatibility**: discovery artifact binding, versioned dynamic tool-catalog checkpoints, and separation of workload identity from delegated user authority; tracked in [#340](https://github.com/agentrust-io/agent-manifest/issues/340) (open)

## Later: v1.0 CoSAI standard (2027)

- Full TSC governance under CoSAI / OASIS Open
- All open spec ambiguities resolved
- Complete conformance certification program
- Multi-language SDK parity (Python, TypeScript, Go, .NET, Rust)
- CoSAI-assigned canonical `@context` URL replacing the provisional v0.1 URL
- Post-quantum profile as first-class (not optional extra)
- Streaming decision trace binding
- Internationalization: docs in Japanese, Simplified Chinese, Korean

## What we will not do

- Replace SPIFFE, SLSA, CycloneDX, or MCP: we compose with these
- Build a centralized manifest registry: the spec is designed for decentralized verification
- Build a proprietary TEE platform: hardware support targets open standards (TPM 2.0, SEV-SNP, TDX) plus OPAQUE as the highest-assurance managed option
- Claim regulatory compliance on your behalf: the spec provides the primitives; compliance requires your organization's legal review

## How to influence the roadmap

Open a GitHub issue with the `spec` label describing the problem you are trying to solve. Feedback from teams running Agent Manifest has priority when choosing what goes into the next revision.
