# Specification Overview

The Agent Manifest Specification v0.1 is a formal RFC 2119 document defining the complete cryptographic identity and provenance standard for AI agents.

**Full specification**: [`spec/agent-manifest-spec-v0.1.md`](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.1.md) (1,500+ lines)

## Structure

| Section | Content |
|---------|---------|
| 1  -  Problem Statement | The agent attestation gap; why software attestation is insufficient |
| 2  -  Overview | Design principles, manifest lifecycle, canonical serialization, version negotiation |
| 3  -  Data Model | All 10 artifact bindings, attestation, delegation chain, HITL records, signature, revocation |
| 4  -  Cryptographic Protocols | Standard (Ed25519) and post-quantum (ML-DSA-65) profiles, Merkle tree construction |
| 5  -  Verification Protocol | HTTP endpoint, result schema, evidence pack, revocation protocol |
| 6  -  Integration Architecture | AGT, cMCP, and MCP integration with field cross-checks |
| 7  -  Threat Model | 10 threat classes addressed; explicit out-of-scope threats |
| 8  -  Conformance | Levels 0–3; 197 conformance tests across 5 modules |
| 9  -  Regulatory Mapping | EU AI Act, DORA, GDPR, HIPAA, PCI-DSS, FedRAMP |
| 10  -  Roadmap | v0.2 targets, v1.0 AAIF submission |

## Conformance test modules

| Module | Tests | Coverage |
|--------|-------|---------|
| AM-BIND | 47 | Artifact binding correctness, hash computation, Merkle trees |
| AM-CRYPTO | 38 | Signature generation and verification, RFC 8785 canonicalization |
| AM-ATTEST | 29 | TEE attestation binding, field cross-checks, per-platform formats |
| AM-VERIFY | 52 | Verification endpoint, mismatch detection, delegation, revocation |
| AM-COMPAT | 31 | AGT integration, cMCP integration, MCP protocol extension |
| **Total** | **197** | |

## Key normative references

| RFC / Standard | Use in spec |
|----------------|------------|
| RFC 8785  -  JCS | All canonical JSON serialization |
| RFC 8032  -  EdDSA | Ed25519 signature scheme |
| RFC 9162  -  CT v2 | Merkle tree construction with domain separation |
| RFC 9334  -  RATS | Remote attestation architecture |
| RFC 9562  -  UUID v7 | Manifest and hop identifiers |
| NIST FIPS 204  -  ML-DSA | Post-quantum signature scheme |
| Sigstore / Rekor | Transparency log integration |
