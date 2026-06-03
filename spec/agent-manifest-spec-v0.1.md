# Agent Manifest Specification

| Field | Value |
|---|---|
| Version | 0.1 — Draft for Review |
| Subtitle | A cryptographic identity and provenance standard for AI agents |
| Authors | Imran Siddique (OPAQUE Systems, CPO) — Creator, Agent Governance Toolkit |
| Status | Draft v0.1 — Proposed Open Standard |
| Date | June 2026 |
| Classification | Confidential — For Design Partners and Standards Review |
| Relationship | Implements: Anthropic Zero Trust for AI Agents (Advanced Tier) \| Extends: OWASP ASI 2026 \| Aligns: CoSAI WS1, EU AI Act Art. 14/15 |
| Target Standards Body | Agentic AI Foundation (AAIF) — Linux Foundation \| Proposed donation alongside AGT |

---

## Abstract

The Agent Manifest is a cryptographically signed, hardware-attestable document that establishes the complete trust surface of an AI agent at deployment time. It binds ten attestable artifacts — system prompt, policy bundle, tool manifest, model identity, RAG corpus, memory baseline, decision trace, A2A delegation chain, supply chain provenance, and human-in-the-loop approval records — into a single tamper-evident identity primitive. A verifying party who holds an Agent Manifest and its accompanying attestation report can prove, without trusting the operator, that a specific agent instance ran specific code under specific policy with specific tools, produced specific decisions, and received specific human oversight. This specification defines the manifest data model, the cryptographic binding protocol, the hardware attestation integration, the verification API, and the conformance requirements for compliant implementations.

## Why This Matters Now

MCP's emergence as the dominant agent-to-tool protocol has made the agent trust surface explicit and exploitable. In the period between January and February 2026, researchers filed over 30 CVEs targeting MCP servers, clients, and tooling. Palo Alto Unit 42 found that with five connected MCP servers, a single compromised server hit a 78.3% attack success rate. The problem is not MCP's protocol design — it is the absence of a standard identity primitive that makes every agent's full execution context verifiable to a third party. A signed JWT proves who called an API. An Agent Manifest proves who the agent was, what it was allowed to do, how it was built, what it decided, who approved it, and whether any of that changed between approval and execution.

## 1. Problem Statement

### 1.1 The Agent Identity Gap

Every entity in a modern enterprise system has a verifiable identity. Users have X.509 certificates and OAuth tokens. Services have SPIFFE SVIDs. APIs have signed JWTs. Containers have image digests. Infrastructure has hardware TPM measurements. AI agents have none of these. An agent calling a tool today presents no unforgeable proof of:

- Which system prompt defined its behavior
- Which model version is running
- Which policy bundle was approved
- Which tools were authorized
- What knowledge base it was grounded on
- Whether its memory has been tampered with
- What decisions it made and why
- Whether a human approved high-stakes actions
- Which agent delegated to it in a multi-agent chain
- Whether its binary matches what was reviewed

This is not an authentication gap — agents can authenticate with certificates and tokens today. It is an attestation gap: the inability to prove, to a third party who does not trust the operator, that the agent running right now is the agent that was approved, with the tools that were authorized, under the policy that was reviewed.

### 1.2 Why Software Attestation Is Insufficient

Existing approaches reduce to operator trust. A software-signed manifest proves the operator intended a configuration. It does not prove the running agent matches it. A privileged operator or compromised dependency can:

- Replace a system prompt in memory after the manifest is signed
- Swap a model version between approval and runtime
- Silently extend tool capabilities via MCP `notifications/tools/list_changed`
- Inject into the RAG corpus without changing the corpus hash
- Forge a human-in-the-loop approval record
- Rewrite audit logs and re-sign with a software-held key

> **The Anthropic Design Test — Applied to Agent Identity**
>
> Anthropic's Zero Trust for AI Agents framework asks: does a control make the attack impossible, or just tedious? Software-signed manifests are tedious controls. A determined operator rewrites them. Hardware-attested manifests are impossible controls — the measurement happens in silicon before any user code runs, and the signing key never leaves the TEE.

### 1.3 The Ten Unattested Surfaces

The following table enumerates the complete agent trust surface. Columns indicate whether each artifact is attestable by software, by hardware, or not at all under current practice.

| # | Artifact | What It Defines | Attack if Unattested | Current Coverage | Agent Manifest |
|---|---|---|---|---|---|
| 1 | System Prompt | Agent persona, behavioral boundaries, safety constraints | Prompt injection silently redefines the agent's goals | None — cleartext in memory | Full binding |
| 2 | Policy Bundle | Cedar/YAML/Rego governance rules; allow/deny decisions | Policy swap grants unapproved permissions silently | AGT + cMCP (software hash) | Hardware-sealed |
| 3 | Tool Manifest | Tool schemas, capability declarations, endpoint bindings | Schema extension silently expands agent capabilities | AGT tool scanner (software) | Full binding |
| 4 | Model Identity | Model family, version, safety alignment level, quantization | Unapproved version may lack safety training | None — operator asserted | Full binding |
| 5 | RAG Corpus | Knowledge base identity, version, ingestion policy | Corpus poisoning changes outputs without touching policy | None — no standard | Merkle root |
| 6 | Memory Baseline | Approved memory state for long-running agents | Memory drift corrupts behavior across sessions undetected | None — no standard | Snapshot hash |
| 7 | Decision Trace | Hardware-signed reasoning record per invocation | No post-hoc accountability for high-stakes decisions | AGT audit (software-signed) | TEE-signed |
| 8 | A2A Delegation | Agent-to-agent trust chain; delegated scope constraints | Orchestrator spoofing; scope laundering across delegation hops | None — no standard | Chain binding |
| 9 | Supply Chain | Container manifest; SLSA provenance; dependency SBOMs | Compromised dependency runs as approved binary | SLSA (build-time only) | Runtime measure |
| 10 | HITL Approvals | Human oversight records with identity and timestamp | EU AI Act Art. 14 violation; no accountability chain | None — no standard | Full binding |

## 2. Specification Overview

### 2.1 Design Principles

The Agent Manifest specification is designed around five principles:

**P1 — Tamper-evidence over tamper-resistance**

The manifest does not prevent tampering by making changes difficult. It makes tampering detectable by a third party who holds the manifest and compares it to a hardware attestation report. Any change to any bound artifact produces a measurement mismatch. Detection is cryptographic, not procedural.

**P2 — Independence from operator trust**

A verifying party must be able to confirm manifest integrity without trusting the operator who produced it. This requires hardware-rooted attestation (TEE measurement) for the binding layer, and a trust root that is not controlled by the entity being attested. OPAQUE's attestation service provides this root; the specification defines the protocol for independent verification.

**P3 — Composability with existing standards**

The manifest does not replace SPIFFE/SPIRE, SLSA, SBOMs, or MCP. It composes with them. Agent identity uses SPIFFE SVIDs. Supply chain provenance uses SLSA attestation and CycloneDX SBOMs. Tool identity uses MCP's tool descriptor schema extended with a manifest binding. Policy identity uses AGT's Cedar bundle format. The manifest is the envelope that binds all of these into a single verifiable artifact.

**P4 — Minimal footprint, maximal verifiability**

The manifest stores hashes and identifiers, not content. The system prompt hash is bound; the system prompt itself is not stored in the manifest. This keeps manifests small, portable, and privacy-preserving, while ensuring that any change to any artifact breaks the hash binding and is therefore detectable.

**P5 — Protocol agnosticism with MCP as the reference implementation**

The manifest is defined for any agent communication protocol. The reference implementation targets MCP because it is currently the dominant agentic wire protocol. When A2A matures, the same manifest structure applies — A2A tool descriptors replace MCP tool descriptors in the Tool Manifest section; the cryptographic binding layer is protocol-agnostic.

### 2.2 Manifest Lifecycle

An Agent Manifest is created once per agent deployment, updated when any bound artifact changes, and verified at every trust boundary crossing. The lifecycle has five phases:

| Phase | Trigger | Actor | Output |
|---|---|---|---|
| 1. Authoring | Agent deployment configuration complete | Agent developer / platform team | Unsigned draft manifest (JSON-LD) |
| 2. Signing | Human security reviewer approves configuration | Security officer / CISO delegate | Signed manifest (JWS with Ed25519 or ML-DSA-65) |
| 3. Attestation | Agent workload launches inside TEE | OPAQUE Confidential Runtime | TEE attestation report binding manifest hash to hardware measurements |
| 4. Verification | Agent crosses a trust boundary (tool call, delegation, audit) | Relying party (MCP server, auditor, regulator) | Verification result: VALID \| MISMATCH \| EXPIRED \| REVOKED |
| 5. Revocation | Any bound artifact changes, compromise detected, or TTL expires | Agent owner or OPAQUE revocation service | Revocation record published to transparency log |

## 3. Data Model

### 3.1 Top-Level Schema

An Agent Manifest is a JSON-LD document conforming to the following schema. All hash fields use SHA-256 unless the implementation has opted into the post-quantum profile, in which case SHAKE-256 is used. Signature fields use Ed25519 for standard deployments and ML-DSA-65 for post-quantum deployments.

```json
{
  "@context": "https://agentmanifest.opaque.co/v0.1/context.json",
  "@type": "AgentManifest",
  "manifest_id": "<UUID v7 — time-ordered>",
  "agent_id": "<SPIFFE URI: spiffe://<trust-domain>/agent/<name>/<instance>",
  "version": "0.1",
  "issued_at": "<ISO 8601 UTC>",
  "expires_at": "<ISO 8601 UTC — default 90 days>",
  "issuer": "<SPIFFE URI of signing authority>",
  "crypto_profile": "standard | post-quantum",
  "artifacts": { "<see section 3.2>" },
  "attestation": { "<see section 3.3>" },
  "delegation_chain": [ "<see section 3.4>" ],
  "hitl_record": { "<see section 3.5>" },
  "signature": { "<see section 3.6>" }
}
```

### 3.2 Artifact Bindings

Each artifact is represented by a binding object containing the artifact's cryptographic hash, its identifier or locator, the binding timestamp, and optionally a structured descriptor. The binding object is what appears in the manifest; the artifact itself is stored separately and referenced by hash.

#### 3.2.1 System Prompt Binding

```json
"system_prompt": {
  "hash": "sha256:<64-hex-chars>",
  "hash_algorithm": "SHA-256 | SHAKE-256",
  "version": "<semantic version or timestamp>",
  "classification": "public | internal | confidential | restricted",
  "language": "<BCP 47 language tag>",
  "safety_level": "<operator-defined safety tier>",
  "bound_at": "<ISO 8601 UTC>"
}
```

The system prompt hash binds the complete byte sequence of the prompt as delivered to the model. Any modification — including whitespace changes, character encoding changes, or appended injections — produces a different hash and invalidates the manifest. Implementations MUST hash the prompt as a UTF-8 byte sequence with no BOM, normalized to NFC.

#### 3.2.2 Policy Bundle Binding

```json
"policy_bundle": {
  "hash": "sha256:<64-hex-chars>",
  "policy_language": "cedar | rego | yaml-agt | composite",
  "version": "<semantic version>",
  "enforcement_mode": "enforce | advisory | audit-only",
  "scope": "<array of AGT policy scope identifiers>",
  "agt_version": "<AGT version that produced this bundle>",
  "bound_at": "<ISO 8601 UTC>"
}
```

The policy bundle hash covers the complete Cedar policy set, including all policy templates and entity schemas. The `enforcement_mode` field is normative — a verifying party MUST reject a manifest whose `enforcement_mode` is `advisory` when the context requires `enforce`. This field aligns with cMCP's `enforcement_mode` attestation field.

#### 3.2.3 Tool Manifest Binding

```json
"tool_manifest": {
  "catalog_hash": "sha256:<64-hex-chars>",
  "tools": [
    {
      "tool_id": "<reverse-domain tool identifier>",
      "name": "<MCP tool name>",
      "server_id": "<SPIFFE URI of MCP server>",
      "schema_hash": "sha256:<64-hex-chars>",
      "description_hash": "sha256:<64-hex-chars>",
      "version": "<semantic version>",
      "permission_scope": "<Cedar entity type>",
      "egress_destinations": ["<FQDN | IP CIDR | none>"]
    }
  ],
  "allow_dynamic_registration": false,
  "rug_pull_policy": "deny-and-alert | deny-and-hold | require-reapproval",
  "bound_at": "<ISO 8601 UTC>"
}
```

The `catalog_hash` is a Merkle root over all individual tool schema hashes. This allows a verifying party to confirm that the full tool catalog is unchanged, and also to prove that a specific tool's schema is included in the approved catalog without revealing the full catalog. The `description_hash` is bound separately from the `schema_hash` because MCP tool poisoning attacks target descriptions rather than schemas — binding the description prevents silent description mutation that the schema hash would not catch.

The `allow_dynamic_registration` field MUST be `false` for production deployments unless a re-approval workflow is bound in the `hitl_record`. Any MCP `notifications/tools/list_changed` event that adds a tool not in the approved catalog MUST trigger a `rug_pull_policy` action and emit a signed evidence event.

#### 3.2.4 Model Identity Binding

```json
"model_identity": {
  "provider": "<model provider identifier>",
  "model_id": "<provider-scoped model identifier>",
  "version": "<model version or hash>",
  "capability_level": "<provider-defined capability tier>",
  "safety_alignment_version": "<RLHF/Constitutional AI version>",
  "quantization": "none | int8 | int4 | fp8 | <other>",
  "deployment_type": "api | local | confidential-inference",
  "model_hash": "sha256:<64-hex-chars> | null-if-api",
  "bound_at": "<ISO 8601 UTC>"
}
```

For API-deployed models, `model_hash` is `null` and the `model_id` and `version` provide the binding. For locally deployed models or models running inside a confidential inference enclave, the `model_hash` is required and MUST match the measured binary. A model version mismatch between the manifest and the running inference service MUST invalidate the manifest.

#### 3.2.5 RAG Corpus Binding

```json
"rag_corpus": {
  "corpus_id": "<operator-assigned stable identifier>",
  "merkle_root": "sha256:<64-hex-chars>",
  "document_count": "<integer>",
  "ingestion_policy_hash": "sha256:<64-hex-chars>",
  "vector_store": "<vector store type and version>",
  "embedding_model": "<embedding model identifier>",
  "last_updated": "<ISO 8601 UTC>",
  "poisoning_scan": {
    "scanner_version": "<scanner identifier>",
    "scanned_at": "<ISO 8601 UTC>",
    "result": "clean | flagged | not-scanned"
  },
  "bound_at": "<ISO 8601 UTC>"
}
```

The `merkle_root` is computed over a sorted array of document hashes. Any document addition, modification, or deletion changes the root and invalidates the manifest. The `ingestion_policy_hash` binds the policy governing what content may enter the corpus — this catches policy changes that would allow previously-rejected content to be ingested without a manifest update.

#### 3.2.6 Memory Baseline Binding

```json
"memory_baseline": {
  "baseline_id": "<UUID v7>",
  "snapshot_hash": "sha256:<64-hex-chars>",
  "memory_type": "none | session | persistent | shared",
  "store": "<memory store type and version>",
  "approved_at": "<ISO 8601 UTC>",
  "ttl_seconds": "<integer>",
  "drift_policy": "deny-on-drift | alert-on-drift | log-only",
  "bound_at": "<ISO 8601 UTC>"
}
```

For agents with session-only memory, this field binds the approved initial memory state. For persistent-memory agents, the `snapshot_hash` represents the last approved memory checkpoint. The `ttl_seconds` field defines the maximum age of a memory snapshot before re-approval is required — this prevents long-running agents from accumulating unreviewed memory drift without bound.

#### 3.2.7 Supply Chain Binding

```json
"supply_chain": {
  "container_image_digest": "sha256:<64-hex-chars>",
  "base_image_digest": "sha256:<64-hex-chars>",
  "slsa_provenance": {
    "level": "1 | 2 | 3 | 4",
    "provenance_uri": "<URI to SLSA attestation>",
    "build_system": "<build system identifier>"
  },
  "sbom": {
    "format": "cyclonedx | spdx",
    "version": "<SBOM spec version>",
    "sbom_hash": "sha256:<64-hex-chars>",
    "sbom_uri": "<URI to SBOM document>"
  },
  "mcp_servers": [
    {
      "server_id": "<SPIFFE URI>",
      "image_digest": "sha256:<64-hex-chars>",
      "slsa_level": "1 | 2 | 3 | 4",
      "phase2_attested": "true | false"
    }
  ],
  "bound_at": "<ISO 8601 UTC>"
}
```

The `container_image_digest` is the primary supply chain binding for the agent runtime. It MUST match the hardware measurement in the TEE attestation report. The `mcp_servers` array binds the supply chain identity of each connected MCP server — `phase2_attested` indicates whether the server is running inside an OPAQUE TEE with its own hardware attestation (Phase 2 / cMCP server-side).

### 3.3 Hardware Attestation Binding

The attestation block binds the manifest to a specific TEE hardware measurement. It is produced by the OPAQUE Confidential Runtime at agent launch time and is not part of the draft manifest — it is appended after the TEE measurement is complete.

```json
"attestation": {
  "platform": "amd-sev-snp | intel-tdx | nvidia-blackwell | aws-nitro",
  "tee_version": "<platform firmware version>",
  "measurement": "<platform-specific launch measurement hex>",
  "manifest_hash_in_report": "sha256:<64-hex-chars>",
  "policy_bundle_hash": "sha256:<64-hex-chars>",
  "enforcement_mode": "enforce | advisory | audit-only",
  "audit_chain_root": "sha256:<64-hex-chars>",
  "audit_key_sealed": true,
  "container_image_digest": "sha256:<64-hex-chars>",
  "report_timestamp": "<ISO 8601 UTC>",
  "report_uri": "<URI to full platform attestation report>",
  "opaque_attestation_service": {
    "service_id": "<SPIFFE URI of OPAQUE attestation service>",
    "service_measurement": "<TEE measurement of attestation service itself>",
    "verification_endpoint": "<HTTPS URI>"
  }
}
```

The `manifest_hash_in_report` field contains the SHA-256 hash of the complete draft manifest (before the attestation block is appended) as it appears in the TEE's measurement registers. This creates a hardware-rooted binding: the TEE measured this specific manifest, and any verifier can confirm this by fetching the platform attestation report and checking the measurement against the manifest hash.

The `audit_key_sealed` field MUST be `true` for production deployments. It indicates that the audit log signing key was generated inside the TEE and has never been exported to operator-readable memory. A manifest with `audit_key_sealed: false` MUST be treated as software-attested and MUST NOT satisfy regulatory requirements that call for hardware-rooted evidence.

### 3.4 A2A Delegation Chain

When an agent is spawned by another agent in a multi-agent system, the delegating agent's identity and scope grant must be bound in the manifest. The `delegation_chain` array is ordered from root principal (human or system) to the current agent.

```json
"delegation_chain": [
  {
    "hop": 0,
    "principal_type": "human | system | agent",
    "principal_id": "<SPIFFE URI | user identifier>",
    "delegated_at": "<ISO 8601 UTC>",
    "scope_grant": {
      "tools": ["<tool_id>"],
      "data_classifications": ["public | internal | confidential | restricted"],
      "max_delegation_depth": "<integer>",
      "ttl_seconds": "<integer>",
      "constraints": ["<Cedar policy fragment>"]
    },
    "delegation_signature": "<Ed25519 | ML-DSA-65 signature by principal>",
    "principal_manifest_id": "<manifest_id of delegating agent, if agent>",
    "principal_attestation_hash": "<attestation hash of delegating agent, if attested>"
  }
]
```

The delegation chain is the cryptographic primitive that closes what we identified as the post-hoc accountability gap — the absence of a tamper-evident proof of the full delegation chain from human principal through orchestrator to tool call. Each hop must be signed by the delegating principal's key. The `scope_grant` at each hop may only be a subset of the scope granted at the previous hop — scope laundering (where a child agent claims broader permissions than its parent granted) is structurally prevented because each hop's scope is signed by the granting agent.

The `max_delegation_depth` field prevents unbounded delegation chains. A verifying party MUST reject a delegation chain whose depth exceeds this value. The default is 3 hops unless explicitly overridden by the security policy.

### 3.5 Human-in-the-Loop Approval Records

For agents operating under EU AI Act Article 14 requirements or any policy that mandates human oversight, the `hitl_record` block captures the human approval event in a cryptographically bound, non-repudiable form.

```json
"hitl_record": {
  "required": "true | false",
  "approvals": [
    {
      "approval_id": "<UUID v7>",
      "approver_id": "<SPIFFE URI | user identifier>",
      "approver_role": "<role identifier>",
      "approved_at": "<ISO 8601 UTC>",
      "approved_scope": {
        "artifacts": ["system_prompt", "policy_bundle", "tool_manifest", "..."],
        "risk_tier": "low | medium | high | critical",
        "approval_duration_seconds": "<integer>",
        "conditions": ["<human-readable condition string>"]
      },
      "approval_signature": "<Ed25519 | ML-DSA-65 signature by approver key>",
      "approval_method": "hardware-key | software-key | mfa-backed",
      "evidence_uri": "<URI to full approval audit record>"
    }
  ],
  "escalation_policy": {
    "trigger": "<Cedar policy fragment defining escalation conditions>",
    "escalation_target": "<SPIFFE URI of escalation authority>",
    "timeout_action": "deny | suspend | alert"
  }
}
```

Each `approval_signature` is produced by the approver's hardware-backed key (FIDO2/passkey at minimum, HSM for high-risk approvals). This satisfies the EU AI Act's requirement that human oversight be meaningful and recorded — a HITL approval record in an Agent Manifest is the first standardized primitive for satisfying Art. 14 in an auditable, hardware-anchored form.

### 3.6 Manifest Signature

```json
"signature": {
  "algorithm": "Ed25519 | ML-DSA-65",
  "key_id": "<key identifier>",
  "key_type": "software | hsm | tee-sealed",
  "signed_at": "<ISO 8601 UTC>",
  "signed_fields": ["artifacts", "delegation_chain", "hitl_record"],
  "signature_value": "<base64url-encoded signature over canonical JSON>",
  "transparency_log": {
    "log_id": "<Rekor or compatible log identifier>",
    "entry_id": "<log entry identifier>",
    "inclusion_proof": "<base64url-encoded inclusion proof>"
  }
}
```

The signature covers the canonical JSON serialization of the `artifacts`, `delegation_chain`, and `hitl_record` fields. The attestation block is NOT covered by the manifest signature — it is produced separately by the hardware and its authenticity is verified via the platform attestation report. This design separates the approval-time signature (what was reviewed and approved) from the runtime measurement (what is actually running).

The `transparency_log` entry provides non-repudiation and enables detection of backdated or forged manifests. All production Agent Manifest implementations MUST publish to a public or consortium transparency log. The signature is NOT sufficient without the transparency log entry for regulatory purposes.

## 4. Cryptographic Protocols

### 4.1 Standard Profile

The standard cryptographic profile uses the following primitives:

| Operation | Algorithm | Key Size | Notes |
|---|---|---|---|
| Manifest signature | Ed25519 | 256-bit | EdDSA over Curve25519. Compact, fast verification. |
| Artifact hashing | SHA-256 | 256-bit output | MUST use NFC-normalized UTF-8 for text artifacts. |
| Merkle tree (corpus, catalog) | SHA-256 | 256-bit | Left-balanced tree; leaf nodes are artifact hashes. |
| Agent identity | SPIFFE SVID (X.509) | 2048-bit RSA or P-256 EC | Issued by trust domain CA; bound to SPIFFE URI. |
| Attestation binding | Platform-native (AMD, Intel, NVIDIA) | Platform-defined | Hardware measurement is platform-specific. |
| Transport encryption | TLS 1.3 with aTLS extension | P-256 or X25519 | Mutual attestation over TLS per cMCP spec. |
| Transparency log | Rekor (Sigstore) or compatible | N/A | RFC 9162 Certificate Transparency variant. |

### 4.2 Post-Quantum Profile

For deployments requiring post-quantum security (classified government, financial services with >10 year sensitivity horizon, sovereign deployments), the post-quantum profile MUST be used. This aligns with AGT's existing ML-DSA-65 implementation.

| Operation | Algorithm | NIST Standard | Notes |
|---|---|---|---|
| Manifest signature | ML-DSA-65 | FIPS 204 | Replaces Ed25519. Larger signatures (~3.3KB) but quantum-resistant. |
| Key exchange | ML-KEM-768 | FIPS 203 | Replaces X25519 in aTLS handshake. |
| Artifact hashing | SHAKE-256 | FIPS 202 | Extendable output function; replaces SHA-256. |
| Hybrid mode | Ed25519 + ML-DSA-65 | Both | Transition period: both signatures required and verified. |

The `crypto_profile` field in the manifest header MUST be set to `post-quantum` when using this profile. A verifying party that supports only the standard profile MUST reject a post-quantum manifest rather than silently falling back — this prevents downgrade attacks during the transition period.

## 5. Verification Protocol

### 5.1 Verification Endpoint

An Agent Manifest implementation MUST expose a verification endpoint that accepts a manifest ID or manifest document and returns a structured verification result. The endpoint MUST be reachable from any relying party without prior authentication to the operator.

```json
POST /verify
Content-Type: application/json
{
  "manifest_id": "<UUID v7>",
  "verification_context": {
    "purpose": "tool-call | audit | delegation | regulatory",
    "verifier_id": "<SPIFFE URI of verifying party>",
    "required_fields": ["system_prompt", "policy_bundle", "tool_manifest"],
    "enforce_hitl": "true | false",
    "enforce_attestation": "true | false",
    "min_slsa_level": "1 | 2 | 3 | 4"
  }
}
```

### 5.2 Verification Result Schema

```json
{
  "verification_id": "<UUID v7>",
  "manifest_id": "<UUID v7>",
  "verified_at": "<ISO 8601 UTC>",
  "result": "VALID | MISMATCH | EXPIRED | REVOKED | INCOMPLETE",
  "attestation_verified": "true | false",
  "fields_verified": {
    "system_prompt": "MATCH | MISMATCH | NOT_BOUND",
    "policy_bundle": "MATCH | MISMATCH | NOT_BOUND",
    "tool_manifest": "MATCH | MISMATCH | NOT_BOUND",
    "model_identity": "MATCH | MISMATCH | NOT_BOUND",
    "rag_corpus": "MATCH | MISMATCH | NOT_BOUND",
    "memory_baseline": "MATCH | MISMATCH | NOT_BOUND | EXPIRED",
    "supply_chain": "MATCH | MISMATCH | NOT_BOUND",
    "delegation_chain": "VALID | INVALID | NOT_PRESENT",
    "hitl_record": "APPROVED | EXPIRED | NOT_REQUIRED | MISSING"
  },
  "mismatch_details": [
    {
      "field": "<field name>",
      "expected_hash": "<hash in manifest>",
      "actual_hash": "<hash of running artifact>",
      "delta_detected_at": "<ISO 8601 UTC>"
    }
  ],
  "evidence_pack": {
    "trace_id": "<TRACE envelope ID>",
    "signed_by": "<TEE-sealed key identifier>",
    "pack_hash": "sha256:<64-hex-chars>",
    "pack_uri": "<URI to full evidence pack>"
  },
  "verification_signature": "<Ed25519 | ML-DSA-65 signature by OPAQUE attestation service>"
}
```

### 5.3 Verification Semantics

A `VALID` result means all of the following are true:

- The manifest signature is valid and the manifest is present in the transparency log
- The TEE attestation report confirms the manifest hash is bound to the hardware measurement
- All fields specified in `required_fields` match their running artifacts
- The manifest has not expired
- The manifest has not been revoked
- If `enforce_hitl` is `true`, at least one HITL approval is present, valid, and not expired
- If `enforce_attestation` is `true`, `audit_key_sealed` is `true` in the attestation block

A `MISMATCH` result means at least one required field does not match its running artifact. The `mismatch_details` array MUST enumerate every mismatched field. A relying party receiving a `MISMATCH` MUST NOT proceed with the operation that triggered verification.

## 6. Integration Architecture

### 6.1 Integration with AGT

The Agent Manifest is the attestation layer above AGT's policy enforcement layer. AGT evaluates policy decisions; the manifest proves those decisions were made under the approved policy, by the approved agent, using the approved tools. The integration points are:

| AGT Component | Agent Manifest Integration Point |
|---|---|
| Cedar policy engine | `policy_bundle.hash` binds the policy bundle that AGT loads at startup. Policy bundle hash in the manifest MUST match `policy_bundle_hash` in the cMCP attestation report. |
| Tool-definition scanner | `tool_manifest.catalog_hash` is the Merkle root over all tool schema and description hashes that AGT's scanner approved. Any scanner-detected drift produces a mismatch. |
| Audit chain (Decision BOM) | `decision_trace` binding points to AGT's hash-chained audit. The audit signing key is the same key that is TEE-sealed and whose root hash appears in `audit_chain_root`. |
| Agent identity (SPIFFE/DID) | `agent_id` in the manifest MUST match the SPIFFE SVID presented by the agent at every tool call. Identity continuity is the chain that links the manifest to the running agent. |
| Compliance export | The verification result (section 5.2) is the AGT compliance export for external regulators — it replaces the current SOC 2 / NIST AI RMF export with a hardware-signed equivalent. |

### 6.2 Integration with cMCP

The Agent Manifest and cMCP are complementary primitives that operate at different layers of the same trust stack. cMCP attests the gateway enforcement layer; the Agent Manifest attests the complete agent identity surface. Their attestation fields overlap deliberately:

| Field | cMCP Attestation | Agent Manifest | Relationship |
|---|---|---|---|
| Policy bundle hash | `policy_bundle_hash` in TEE report | `policy_bundle.hash` | MUST be identical. Verifier cross-checks both. |
| Enforcement mode | `enforcement_mode` in TEE report | `policy_bundle.enforcement_mode` | MUST match. Conflict = attestation failure. |
| Audit chain root | `audit_chain_root` in TEE report | Referenced by `decision_trace.audit_chain_uri` | Same audit chain; manifest provides the identity context. |
| Container image digest | `container_image_digest` in TEE report | `supply_chain.container_image_digest` | MUST be identical. Verifier cross-checks both. |
| Tool catalog hash | Catalog hash in cMCP runtime | `tool_manifest.catalog_hash` (Merkle root) | cMCP enforces; manifest binds what was approved. |

### 6.3 Integration with MCP Protocol

At the protocol level, Agent Manifest integration with MCP requires two additions to the standard MCP handshake:

#### 6.3.1 Manifest Presentation at Connection

When an agent's MCP client connects to an MCP server, the client SHOULD include the agent's manifest ID and verification endpoint in the `initialize` request:

```json
{
  "method": "initialize",
  "params": {
    "clientInfo": {
      "name": "<agent name>",
      "version": "<agent version>",
      "agentManifestId": "<UUID v7>",
      "agentManifestVerificationEndpoint": "<HTTPS URI>"
    }
  }
}
```

An MCP server implementing the Agent Manifest extension SHOULD verify the manifest before servicing any tool calls. For cMCP Phase 2 servers running inside an OPAQUE TEE, this verification is performed inside the TEE and the result is included in the per-call evidence pack.

#### 6.3.2 Manifest Binding in Tool Call Evidence

Every tool call evidence record (TRACE envelope) produced by cMCP MUST include the agent's manifest ID and the verification result at the time of the call:

```json
{
  "trace_id": "<UUID v7>",
  "agent_id": "<SPIFFE URI>",
  "agent_manifest_id": "<UUID v7>",
  "manifest_verification_result": "VALID | MISMATCH | EXPIRED",
  "tool_id": "<reverse-domain tool identifier>",
  "policy_hash": "sha256:<64-hex-chars>",
  "catalog_hash": "sha256:<64-hex-chars>",
  "decision": "allow | deny | require-approval",
  "decision_reason": "<Cedar policy fragment that made this decision>",
  "payload_classification": "public | internal | confidential | restricted",
  "egress_destination": "<FQDN | IP | none>",
  "hitl_required": "true | false",
  "hitl_approval_id": "<UUID v7> | null",
  "timestamp": "<ISO 8601 UTC>",
  "tee_measurement": "<platform-specific measurement>",
  "signature": "<Ed25519 | ML-DSA-65 by TEE-sealed key>"
}
```

## 7. Threat Model

### 7.1 Threat Classes Addressed

| Threat | Description | Without Agent Manifest | With Agent Manifest |
|---|---|---|---|
| T1 — Prompt Substitution | System prompt replaced in memory between approval and runtime | Undetectable. No binding exists. | `system_prompt.hash` mismatch immediately detectable at verification. |
| T2 — Policy Swap | Cedar policy bundle replaced with permissive policy | Detectable by AGT hash check (software). Bypassable by root. | `policy_bundle.hash` bound to TEE measurement. Hardware-impossible to swap silently. |
| T3 — Tool Rug Pull | MCP server mutates tool definition after approval | Detectable by AGT scanner (software). Re-hash bypassable. | `tool_manifest.description_hash` bound. Any mutation breaks `catalog_hash` Merkle root. |
| T4 — Model Substitution | Different model version runs than was approved | Undetectable. No standard binding. | `model_identity.version` bound. API models: version check at call time. Local models: binary hash. |
| T5 — RAG Corpus Poisoning | Malicious documents injected into knowledge base | Undetectable without corpus audit. | `rag_corpus.merkle_root` changes. Manifest invalidated. Verifier detects before agent runs. |
| T6 — Scope Laundering | Sub-agent claims broader permissions than delegating agent granted | Undetectable. No delegation chain standard. | `delegation_chain.scope_grant` is signed at each hop. Broader scope fails signature verification. |
| T7 — Rogue Administrator | Operator with root access rewrites audit logs or policy | Bypassable. Software signing key is operator-held. | `audit_key_sealed: true`. Key never leaves TEE. Log reconstruction hardware-impossible. |
| T8 — HITL Forgery | Human approval record fabricated without actual human review | Undetectable without physical audit. | `approval_signature` produced by approver hardware key. Forgery requires key compromise. |
| T9 — Supply Chain Compromise | Malicious dependency runs as approved binary | SLSA covers build-time. Runtime drift undetected. | `container_image_digest` in TEE measurement. Modified binary produces measurement mismatch. |
| T10 — Memory Drift | Long-running agent accumulates unreviewed memory changes | Undetectable. No memory baseline standard. | `memory_baseline.snapshot_hash` bound. `ttl_seconds` forces re-approval of memory state. |

### 7.2 Out of Scope

The following threats are explicitly out of scope for this specification:

- **Semantic prompt injection at the model layer** — the manifest proves what prompt was approved; it cannot prevent a model from being misled by adversarial inputs within that prompt's scope.
- **Model weight poisoning** — the `model_identity` binding attests which model is running; it does not attest the model's internal weights for locally-deployed models beyond the binary hash.
- **Side-channel attacks on the TEE** — hardware vulnerabilities in AMD SEV-SNP, Intel TDX, or NVIDIA Blackwell that allow measurement extraction are out of scope. These are platform-level threats addressed by hardware vendors.
- **Denial of service against the verification endpoint** — availability of the verification service is an operational concern, not a correctness concern.
- **Human approver compromise** — if an authorized approver's hardware key is compromised, the HITL record is valid despite the fraudulent approval. Key management and approver identity assurance are out of scope.

## 8. Conformance Requirements

### 8.1 Implementation Levels

| Level | Name | Requirements | Use Case |
|---|---|---|---|
| Level 0 | Software-only | All artifact bindings. Standard crypto profile. Transparency log publication. No TEE requirement. | Development, staging, non-regulated environments. |
| Level 1 | TEE-attested | Level 0 plus: TEE attestation block. `audit_key_sealed: true`. `container_image_digest` verified by hardware. | Enterprise production. Satisfies EU AI Act Art. 15 (cybersecurity). |
| Level 2 | Full stack | Level 1 plus: All 10 artifacts bound. HITL approvals present. Delegation chain for multi-agent. Phase 2 cMCP for all MCP servers. | Regulated industries. Satisfies DORA Art. 9, OCC AI guidance, GDPR Art. 32. |
| Level 3 | Post-quantum | Level 2 plus: ML-DSA-65 signatures. ML-KEM-768 key exchange. SHAKE-256 hashing. | Sovereign deployments, classified, financial services with long-horizon sensitivity. |

### 8.2 Conformance Test Suite

A conformant Agent Manifest implementation MUST pass all tests in the reference test suite. The suite is organized into four modules:

| Module | Tests | Coverage |
|---|---|---|
| AM-BIND | 47 tests | Artifact binding correctness: hash computation, normalization, Merkle tree construction, schema validation. |
| AM-CRYPTO | 38 tests | Signature generation and verification: Ed25519, ML-DSA-65, hybrid, transparency log inclusion. |
| AM-ATTEST | 29 tests | TEE attestation binding: manifest hash in report, field cross-checks with cMCP, `audit_key_sealed` enforcement. |
| AM-VERIFY | 52 tests | Verification endpoint: result schema, mismatch detection, delegation chain validation, HITL verification. |
| AM-COMPAT | 31 tests | AGT integration, cMCP integration, MCP protocol extension, SLSA provenance binding. |

Total: 197 conformance tests. The test suite will be published as an open-source repository alongside the AGT donation to AAIF. Conformance claims MUST reference a specific test suite version and MUST include a passing test run against the reference implementation.

## 9. Regulatory Mapping

### 9.1 EU AI Act

| Article | Requirement | Agent Manifest Satisfaction |
|---|---|---|
| Art. 13 — Transparency | High-risk AI systems must be transparent about their operation | `agent_id`, `model_identity`, and `tool_manifest` provide the disclosure primitive for what the agent is and what it can do. |
| Art. 14 — Human Oversight | High-risk AI must allow humans to understand and intervene; oversight measures documented | `hitl_record` provides the first standardized, hardware-anchored human oversight record. `approval_signature` by hardware key satisfies non-repudiation. |
| Art. 15 — Accuracy and Cybersecurity | High-risk AI must be resilient to errors; cybersecurity measures documented | TEE attestation + `container_image_digest` satisfies the cybersecurity measure documentation requirement. Mismatch detection satisfies resilience. |
| Art. 26 — Obligations for Deployers | Deployers must monitor operation and report serious incidents; logging required | `decision_trace` + `audit_chain_root` provides the monitoring log. TEE-sealed signing key satisfies tamper-evidence requirement. |
| Art. 12 — Record-keeping | High-risk AI must keep logs automatically; logs must be accurate | `audit_key_sealed: true` satisfies the accuracy requirement — logs cannot be retroactively altered without detection. |

### 9.2 DORA (EU) and OCC (US)

| Framework | Requirement | Agent Manifest Satisfaction |
|---|---|---|
| DORA Art. 9 | ICT systems must be resilient; evidence of what ran and when | Verification result + `evidence_pack` provides per-invocation evidence of what agent ran, under what policy, at what time. Hardware-signed. |
| DORA Art. 28 | Third-party ICT risk management; independent oversight | OPAQUE as independent attestation authority. Verification endpoint reachable by regulator without operator involvement. |
| OCC AI Risk Guidance | Banks must document AI model governance; audit trails required | `hitl_record` + `decision_trace` together satisfy the model governance documentation and audit trail requirements. |
| NIST AI RMF — GOVERN 1.7 | Policies for AI risk management documented and implemented | `policy_bundle.hash` bound to hardware attestation proves policy implementation, not just documentation. |

## 10. Roadmap and Standards Path

### 10.1 Version 0.1 — This Specification

- Complete data model for all 10 artifacts
- Cryptographic protocol definitions for standard and post-quantum profiles
- Verification API specification
- TEE attestation binding protocol
- Conformance test suite (197 tests)
- Reference implementation targeting AGT + cMCP on OPAQUE

### 10.2 Version 0.2 — Design Partner Feedback

Targets: Q3 2026. Input from ServiceNow, JPMC, Across AI, and sovereign AI partners.

- Memory baseline protocol for stateful agents (v0.1 defines the binding; v0.2 defines the checkpoint protocol)
- RAG corpus incremental update protocol — how to bind a delta without re-hashing the full corpus
- Multi-model manifest — binding for agents that use different models for different subtasks
- Federated verification — cross-organizational manifest verification without shared infrastructure
- A2A delegation chain revocation — how to invalidate a mid-chain delegation without revoking the full manifest

### 10.3 Version 1.0 — Proposed AAIF Standard

Target: Q1 2027. Submission to AAIF alongside the AGT donation.

- Finalized data model with no breaking changes from v0.2
- Interoperability validated with at least three independent implementations
- AAIF working group review and endorsement
- Reference implementation published as AAIF project
- Conformance certification program defined

### 10.4 Relationship to Existing Standards

| Standard | Relationship |
|---|---|
| SPIFFE/SPIRE | Agent Manifest uses SPIFFE SVIDs for `agent_id` and `principal_id`. Agent Manifest extends, not replaces, SPIFFE. |
| SLSA | `supply_chain.slsa_provenance` references SLSA attestations. Agent Manifest adds runtime measurement on top of SLSA build-time provenance. |
| CycloneDX / SPDX (SBOM) | `supply_chain.sbom` references a CycloneDX or SPDX SBOM. Agent Manifest binds the SBOM hash; it does not replace SBOM tooling. |
| MCP (Anthropic / AAIF) | Agent Manifest extends MCP's `initialize` handshake and tool call protocol. It is protocol-agnostic but MCP is the reference implementation. |
| A2A (Google / Linux Foundation) | `delegation_chain` supports A2A-style orchestration. The chain binding is protocol-agnostic. |
| Sigstore / Rekor | `signature.transparency_log` uses Rekor or a compatible CT log. Sigstore tooling (cosign) can sign manifests in the standard profile. |
| OpenTelemetry | `decision_trace` integrates with OTel spans. Each manifest-bound tool call produces an OTel span with the manifest ID as a baggage item. |
| CoSAI WS1 | `supply_chain` provenance aligns with CoSAI Working Stream 1 (AI supply chain security). Agent Manifest is a candidate for CoSAI WS1 recommendation. |

## 11. Appendix

### A. Glossary

| Term | Definition |
|---|---|
| Agent Manifest | The cryptographically signed, hardware-attestable document defined by this specification. |
| Attestation | A hardware-produced measurement that proves what code is running inside a TEE without trusting the operator. |
| A2A | Agent-to-Agent protocol. A wire protocol for inter-agent communication, currently governed by the Linux Foundation. |
| AGT | Agent Governance Toolkit. The open-source agent governance framework created by Imran Siddique; reference implementation of this specification's software layer. |
| Catalog Hash | Merkle root over all tool schema and description hashes in the approved tool catalog. |
| cMCP | Confidential MCP. OPAQUE's hardware-attested MCP gateway; the reference implementation of this specification's attestation layer. |
| Decision BOM | Decision Bill of Materials. AGT's per-audit-record structure capturing the inputs, policy decision, and outcome for each governance decision. |
| Delegation Chain | The ordered sequence of principals and scope grants from root human principal to the current agent. |
| HITL | Human-in-the-Loop. A human oversight event that is recorded and bound in the manifest. |
| Manifest ID | A UUID v7 (time-ordered) that uniquely identifies a specific version of an Agent Manifest. |
| Merkle Root | The root hash of a Merkle tree over a set of artifact hashes. Changing any artifact changes the root. |
| ML-DSA-65 | Module Lattice-based Digital Signature Algorithm, parameter set 65. NIST FIPS 204. Post-quantum signature scheme. |
| Rug Pull | An attack where a previously-approved MCP server silently mutates its tool definitions after the security review concluded. |
| Scope Laundering | An attack where a sub-agent claims broader permissions than its delegating principal granted. |
| TEE | Trusted Execution Environment. Hardware-isolated memory region (AMD SEV-SNP, Intel TDX, NVIDIA Blackwell) where code runs protected from the host OS and operator. |
| TRACE Envelope | The portable, hardware-signed evidence artifact produced by cMCP for every tool call. Contains the verification result plus per-call decision evidence. |

### B. Change Log

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | June 2026 | Imran Siddique | Initial draft. Complete data model, 10 artifacts, cryptographic protocols, verification API, conformance requirements, regulatory mapping. |

### C. Acknowledgments

This specification builds on architectural work developed across the Agent Governance Toolkit (AGT), the Confidential MCP (cMCP) specification, the Opaque Systems Agent Trust Platform design, and prior research into Cryptographic Agent Provenance and Verifiable Agent Delegation. The delegation chain design is informed by the IATP (Inter-Agent Trust Protocol) architecture developed in the context of the Agent Internet proposal. The post-quantum profile extends AGT's existing ML-DSA-65 implementation. The HITL record design is informed by the EU AI Act Art. 14 implementation guidance from the European AI Office.

---

*Agent Manifest Specification v0.1 — OPAQUE Systems — June 2026*
