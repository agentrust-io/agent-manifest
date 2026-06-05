# Roadmap

## Now — v0.1 developer preview (June 2026)

Launching at Confidential Computing Summit, June 23 2026.

- Specification: all 10 artifact bindings, conformance levels 0–3, 197 conformance tests
- Python SDK: signing, verification, hardware attestation (TPM / SEV-SNP / TDX / OPAQUE), CLI
- Standard crypto profile: Ed25519, SHA-256, RFC 8785
- Post-quantum profile: ML-DSA-65 (NIST FIPS 204), SHAKE-256 (via `[pq]` extra)
- Integration architecture documented: AGT, cMCP, MCP

**Not in v0.1**: TypeScript SDK, Go SDK, .NET SDK, streaming decision trace, multi-agent delegation UI, AAIF submission.

## Next — v0.2 (Q3 2026)

Driven by design-partner feedback from the CC Summit. Current candidates:

- **HITL approval scheme clarification** — specify whether hybrid mode applies to approver signatures; document approver key rotation
- **Policy bundle test vector** — add Merkle root test vector for composite bundles (Section 3.2.2)
- **RAG corpus poisoning precedence** — explicit rule for HITL override of `poisoning_scan.result: flagged`
- **Memory baseline TTL carve-out** — reconcile artifact-only refresh exception with the immutability rule
- **Delegation non-Cedar fallback** — static scope narrowing for verifiers without Cedar support
- **TypeScript SDK** — community contribution welcome; see issue tracker for scope
- **Verification server improvements** — evidence pack format, revocation endpoint

v0.2 will go through the RFC process (14-day comment period) for any normative changes.

## Later — v1.0 AAIF standard (2027)

- Full TSC governance under AAIF
- All open spec ambiguities resolved
- Complete conformance certification program
- Multi-language SDK parity (Python, TypeScript, Go, .NET, Rust)
- AAIF-assigned canonical `@context` URL replacing the provisional v0.1 URL
- Post-quantum profile as first-class (not optional extra)
- Streaming decision trace binding
- Internationalization: docs in Japanese, Simplified Chinese, Korean

## What we will not do

- Replace SPIFFE, SLSA, CycloneDX, or MCP — we compose with these
- Build a centralized manifest registry — the spec is designed for decentralized verification
- Build a proprietary TEE platform — hardware support targets open standards (TPM 2.0, SEV-SNP, TDX) plus OPAQUE as the highest-assurance managed option
- Claim regulatory compliance on your behalf — the spec provides the primitives; compliance requires your organization's legal review

## How to influence the roadmap

Open a GitHub issue with the `spec` label describing the problem you are trying to solve. Design partner feedback from the CC Summit period (June–September 2026) has priority for v0.2 scope decisions.
