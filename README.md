<p align="center">
  <img src="docs/assets/icon.svg" width="96" height="96" alt="Agent Manifest"/>
</p>

# Agent Manifest

### Prove what your agent was, not just who called it

<p align="center">
  <a href="https://agentrust-io.github.io/agent-manifest">
    <img src="https://img.shields.io/badge/Documentation-agentrust--io.github.io%2Fagent--manifest-7c3aed?style=for-the-badge" alt="Documentation" height="36">
  </a>
</p>

<p align="center">
  <strong>
    <a href="#quick-start">Quick Start</a> ·
    <a href="#the-10-attested-artifacts">10 Artifacts</a> ·
    <a href="spec/agent-manifest-spec-v0.1.md">Specification</a> ·
    <a href="https://pypi.org/project/agent-manifest/">PyPI</a> ·
    <a href="CHANGELOG.md">Changelog</a>
  </strong>
</p>

[![CI](https://github.com/agentrust-io/agent-manifest/actions/workflows/ci.yml/badge.svg)](https://github.com/agentrust-io/agent-manifest/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/agent-manifest?label=PyPI)](https://pypi.org/project/agent-manifest/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/agentrust-io/agent-manifest/badge)](https://scorecard.dev/viewer/?uri=github.com/agentrust-io/agent-manifest)
[![Spec](https://img.shields.io/badge/Spec-v0.1_·_197_conformance_tests-0ea5e9)](spec/agent-manifest-spec-v0.1.md)
[![AAIF](https://img.shields.io/badge/Targeting-AAIF_%2F_Linux_Foundation-6366f1)](CHARTER.md)

> **Developer Preview** — launching at Confidential Computing Summit, June 23 2026. May have breaking changes before v1.0.

A cryptographically signed, hardware-attestable document that establishes the complete trust surface of an AI agent at deployment. Bind ten artifacts — system prompt, policy bundle, tool schemas, model identity, RAG corpus, memory state, decision trace, A2A delegation chain, supply chain provenance, and human-in-the-loop approvals — into a single tamper-evident identity primitive.

---

## The problem

A signed JWT proves who called an API. It proves nothing about the agent that made the call.

An AI agent calling a tool today presents no unforgeable proof of:

- Which system prompt defined its behavior (a tampered prompt is a different agent)
- Which model version ran (an unapproved version may lack safety alignment)
- Which policy bundle was in force (a swapped policy grants unapproved permissions)
- Whether a human approved high-stakes actions (EU AI Act Art. 14 requires this)
- Whether its container matches what was reviewed (supply chain attacks go undetected)

This is not an authentication gap — agents can authenticate with certificates and tokens. It is an **attestation gap**: the inability to prove, to a third party who does not trust the operator, that the agent running right now is the agent that was approved.

Software-signed manifests don't close this gap. A privileged operator can swap a system prompt in memory after signing, change a model version between approval and runtime, or forge an approval record. Hardware-attested manifests make these attacks structurally impossible — the measurement happens in silicon before any user code runs, and the signing key never leaves the TEE.

---

## Quick Start

```bash
pip install "agent-manifest[cli]"
```

```bash
# Generate a signing key pair
manifest keygen -d ./keys/

# Sign a manifest
manifest sign draft.json --key keys/private.hex -o signed.json

# Verify
manifest verify signed.json   # VALID
```

Python SDK:

```python
from agent_manifest import (
    Manifest, ArtifactBindings,
    SystemPromptBinding, PolicyBundleBinding, ModelIdentityBinding,
    CryptoProfile, DeploymentType, EnforcementMode, PolicyLanguage,
    generate_ed25519, Ed25519Signer,
)
from agent_manifest._types import HashValue, ManifestId
from datetime import datetime, timedelta, timezone
import hashlib

now = datetime.now(timezone.utc)
prompt = open("system_prompt.txt").read()
prompt_hash = "sha256:" + hashlib.sha256(prompt.encode()).hexdigest()

manifest = Manifest(
    manifest_id=ManifestId("019236ab-cdef-7000-8000-000000000001"),
    agent_id="spiffe://trust.acme.co/agent/payments/prod",
    issued_at=now,
    expires_at=now + timedelta(days=90),
    issuer="spiffe://trust.acme.co/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(
        system_prompt=SystemPromptBinding(
            hash=HashValue(prompt_hash),
            hash_algorithm="SHA-256",
            version="1.0.0",
            classification="confidential",
            bound_at=now,
        ),
        policy_bundle=PolicyBundleBinding(
            hash=HashValue("sha256:" + "b" * 64),
            policy_language=PolicyLanguage.cedar,
            version="1.0.0",
            enforcement_mode=EnforcementMode.enforce,
            bound_at=now,
        ),
        model_identity=ModelIdentityBinding(
            provider="anthropic",
            model_id="claude-sonnet-4-6",
            version="20251001",
            deployment_type=DeploymentType.api,
            bound_at=now,
        ),
    ),
)

keypair = generate_ed25519()
signer = Ed25519Signer(keypair)
signed = manifest.model_dump(mode="json", by_alias=True)
signed["signature"] = signer.sign(signed)
```

Full walkthrough: [docs/getting-started.md](docs/getting-started.md) — Level 0 in 15 minutes, Level 1 (TPM) in 20.

---

## How it works

```
Agent config ─ 10 artifacts
   │  hash + bind, then sign (Ed25519 / ML-DSA-65)
   ▼
Manifest (JSON-LD)
   │  measured in silicon — TEE: TPM / SEV-SNP / TDX / GPU-CC
   │  signing key sealed, never exported
   ▼
Transparency log (Rekor) ─ append-only, public
   │
   ▼
Verifier (no operator trust): hashes match? · measurement matches? · revoked / expired?
   │
   ├─ MATCH ✓     → it's the agent that was approved
   └─ MISMATCH ✗  → drift · swapped model · poisoned corpus · imposter
        answers both: the builder ("still governed the way I built it?")
                      and any third party (auditor / CISO / regulator)
```

A verifying party holding a manifest and its attestation report can prove — without trusting the operator — that a specific agent ran specific code under specific policy, produced specific decisions, and received specific human oversight.

---

## The 10 attested artifacts

| # | Artifact | What it proves | Attack if unattested |
|---|----------|----------------|----------------------|
| 1 | System Prompt | Exact prompt defining persona and safety constraints | Prompt injection redefines agent goals |
| 2 | Policy Bundle | Cedar/Rego/YAML governance rules in force | Policy swap grants unapproved permissions |
| 3 | Tool Manifest | Tool schemas and endpoint bindings | Schema extension silently expands capabilities |
| 4 | Model Identity | Model family, version, safety alignment | Unapproved version may lack safety training |
| 5 | RAG Corpus | Knowledge base identity (Merkle root) | Corpus poisoning changes outputs silently |
| 6 | Memory Baseline | Approved memory state with TTL | Memory drift corrupts long-running agents |
| 7 | Decision Trace | Hardware-signed audit chain root | No accountability for high-stakes decisions |
| 8 | A2A Delegation | Agent-to-agent trust chain | Orchestrator spoofing, scope laundering |
| 9 | Supply Chain | Container digest, SLSA provenance, SBOMs | Compromised dependency runs as approved binary |
| 10 | HITL Approvals | Human oversight records with identity and timestamp | EU AI Act Art. 14 violation |

---

## Hardware providers

| Provider | Platform | Assurance | Install |
|----------|----------|-----------|---------|
| `SoftwareProvider` | Any (Level 0 only) | Software | Built-in |
| `TPMProvider` | Any VM with Trusted Launch, AWS Nitro | Medium | `apt install tpm2-tools` |
| `SEVSNPProvider` | Azure Confidential Computing (DCasv5), GCP Confidential Space (N2D), AWS Nitro | High | Requires `/dev/sev-guest` |
| `TDXProvider` | Azure Confidential Computing (DCedsv5), GCP Confidential Space (C3) | High | Requires `/dev/tdx-guest` |
| `GPUCCProvider` _(v0.2)_ | NVIDIA H100/H200/Blackwell (CC mode) | High | NVIDIA Remote Attestation Service (NRAS) |
| `OPAQUEProvider` | Opaque Managed Runtime | High | Set `OPAQUE_ATTESTATION_URL` (explicit opt-in) |

Provider auto-selects: `SEV-SNP → TDX → TPM → software`. `OPAQUEProvider` is explicit opt-in via `OPAQUE_ATTESTATION_URL`.

```python
from agent_manifest._auto_provider import select_provider

provider = select_provider(level=1)   # raises if no hardware available
provider.extend_manifest_hash(manifest_dict)
report = provider.get_attestation_report()
# report.platform: "tpm" | "amd-sev-snp" | "intel-tdx" | "gpu-cc" | "opaque"
```

---

## Conformance levels

| Level | Name | Requirements | Use case |
|-------|------|-------------|---------|
| 0 | Software-only | All artifact bindings, Ed25519, transparency log | Development, staging |
| 1 | TEE-attested | + TEE attestation, `audit_key_sealed: true` | Enterprise production, EU AI Act Art. 15 |
| 2 | Full stack | + All 10 artifacts, HITL approvals, Phase 2 cMCP, 180-day log retention | Regulated industries, DORA Art. 9 |
| 3 | Post-quantum | + ML-DSA-65 (NIST FIPS 204), ML-KEM-768, SHAKE-256 | Sovereign, classified, long-horizon financial |

---

## Specification

The [Agent Manifest Specification v0.1](spec/agent-manifest-spec-v0.1.md) is a formal RFC 2119 document covering:

- Complete data model for all 10 artifact bindings
- Cryptographic protocol: Ed25519 / ML-DSA-65 / hybrid, RFC 8785 canonical JSON
- Hardware attestation integration: TPM, SEV-SNP, TDX, OPAQUE
- Verification API with error schema and revocation protocol
- Integration architecture for AGT, cMCP, and MCP
- Regulatory mapping: EU AI Act, DORA, GDPR, HIPAA, PCI-DSS, FedRAMP
- **197 conformance tests** across 5 modules (AM-BIND, AM-CRYPTO, AM-ATTEST, AM-VERIFY, AM-COMPAT)

Being submitted to the [Agentic AI Foundation (AAIF)](CHARTER.md) under the Linux Foundation alongside AGT. Target: September 2026.

---

## Standards alignment

| Standard | Coverage |
|----------|----------|
| OWASP Agentic AI Top 10 | Addresses all 10 ASI categories with deterministic, attestable controls |
| NIST AI RMF 1.0 | GOVERN (identity), MAP (artifacts), MEASURE (conformance), MANAGE (revocation) |
| EU AI Act Art. 13–15 | Transparency (model identity), HITL (Art. 14), supports Art. 15 (cybersecurity) at Level 1 |
| DORA Art. 9 | Attestation chain + 180-day log retention (Level 2) |
| CoSAI WS1 | Secure-by-Design Principles, MCP Security Taxonomy |

---

## Install

| Extra | Command | Adds |
|-------|---------|------|
| Core | `pip install agent-manifest` | Signing, verification, Pydantic models |
| CLI | `pip install "agent-manifest[cli]"` | `manifest` command |
| Server | `pip install "agent-manifest[server]"` | FastAPI verification endpoint |
| Post-quantum | `pip install "agent-manifest[pq]"` | ML-DSA-65 via liboqs |
| All | `pip install "agent-manifest[all]"` | Everything above |

Python 3.11+ required.

---

## Documentation

| | |
|--|--|
| [Getting Started](docs/getting-started.md) | Level 0 in 15 minutes, Level 1 in 20 |
| [Examples](examples/) | Complete manifest JSON for Level 0 and Level 1 |
| [Specification](spec/agent-manifest-spec-v0.1.md) | Full normative spec, 1500+ lines |
| [Architecture Decisions](docs/adr/) | Rationale for cryptographic design choices |
| [Roadmap](ROADMAP.md) | v0.2 candidates, v1.0 AAIF target |
| [Limitations](LIMITATIONS.md) | Honest scope boundaries and layered defense guidance |
| [Full docs site](https://agentrust-io.github.io/agent-manifest) | MkDocs site |

---

## Security

| Tool | Coverage |
|------|----------|
| CodeQL | Python SAST, security-extended queries, weekly |
| bandit | Security linting on every PR |
| pip-audit | Dependency vulnerability scan on every PR |
| Dependabot | pip + GitHub Actions, weekly |
| OpenSSF Scorecard | Weekly scoring, SARIF upload |

See [SECURITY.md](SECURITY.md) for vulnerability reporting. See [LIMITATIONS.md](LIMITATIONS.md) for design boundaries.

---

## Contributing

[Contributing Guide](CONTRIBUTING.md) · [Security Policy](SECURITY.md) · [Changelog](CHANGELOG.md) · [Roadmap](ROADMAP.md)

Using Agent Manifest in production? Add your organization to [ADOPTERS.md](ADOPTERS.md).

## Governance

| Document | Purpose |
|----------|---------|
| [GOVERNANCE.md](GOVERNANCE.md) | Decision-making, roles, contributor ladder |
| [CHARTER.md](CHARTER.md) | Technical charter (LF Projects format, AAIF transition) |
| [MAINTAINERS.md](MAINTAINERS.md) | Maintainers and organizations |
| [ANTITRUST.md](ANTITRUST.md) | Competition law guidelines |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting and response SLAs |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 |

## License

Apache 2.0 — see [LICENSE](LICENSE).
