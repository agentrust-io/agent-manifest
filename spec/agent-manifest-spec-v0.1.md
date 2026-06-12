# Agent Manifest Specification

| Field | Value |
|---|---|
| Version | 0.1 - Draft for Review |
| Subtitle | A cryptographic identity and provenance standard for AI agents |
| Authors | Imran Siddique (AgentTrust) |
| Status | Draft v0.1 - Proposed Open Standard |
| Date | June 2026 |
| Relationship | Extends: OWASP ASI 2026 \| Aligns: CoSAI WS1, EU AI Act Art. 14/15 |
| Target Standards Body | Agentic AI Foundation (AAIF) - Linux Foundation |

---

## Abstract

The Agent Manifest is a cryptographically signed, hardware-attestable document that establishes the complete trust surface of an AI agent at deployment time. It binds ten attestable artifacts - system prompt, policy bundle, tool manifest, model identity, RAG corpus, memory baseline, decision trace, A2A delegation chain, supply chain provenance, and human-in-the-loop approval records - into a single tamper-evident identity primitive. A verifying party who holds an Agent Manifest and its accompanying attestation report can prove, without trusting the operator, that a specific agent instance ran specific code under specific policy with specific tools, produced specific decisions, and received specific human oversight. This specification defines the manifest data model, the cryptographic binding protocol, the hardware attestation integration, the verification API, and the conformance requirements for compliant implementations.

## Why This Matters Now

MCP's emergence as the dominant agent-to-tool protocol has made the agent trust surface explicit and exploitable. In the period between January and February 2026, researchers filed over 30 CVEs targeting MCP servers, clients, and tooling. Palo Alto Unit 42 found that with five connected MCP servers, a single compromised server hit a 78.3% attack success rate. The problem is not MCP's protocol design - it is the absence of a standard identity primitive that makes every agent's full execution context verifiable to a third party. A signed JWT proves who called an API. An Agent Manifest proves who the agent was, what it was allowed to do, how it was built, what it decided, who approved it, and whether any of that changed between approval and execution.

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

This is not an authentication gap - agents can authenticate with certificates and tokens today. It is an attestation gap: the inability to prove, to a third party who does not trust the operator, that the agent running right now is the agent that was approved, with the tools that were authorized, under the policy that was reviewed.

### 1.2 Why Software Attestation Is Insufficient

Existing approaches reduce to operator trust. A software-signed manifest proves the operator intended a configuration. It does not prove the running agent matches it. A privileged operator or compromised dependency can:

- Replace a system prompt in memory after the manifest is signed
- Swap a model version between approval and runtime
- Silently extend tool capabilities via MCP `notifications/tools/list_changed`
- Inject into the RAG corpus without changing the corpus hash
- Forge a human-in-the-loop approval record
- Rewrite audit logs and re-sign with a software-held key

> **The Anthropic Design Test - Applied to Agent Identity**
>
> Anthropic's Zero Trust for AI Agents framework asks: does a control make the attack impossible, or just tedious? Software-signed manifests are tedious controls. A determined operator rewrites them. Hardware-attested manifests are impossible controls - the measurement happens in silicon before any user code runs, and the signing key never leaves the TEE.

### 1.3 The Ten Unattested Surfaces

The following table enumerates the complete agent trust surface. Columns indicate whether each artifact is attestable by software, by hardware, or not at all under current practice.

| # | Artifact | What It Defines | Attack if Unattested | Current Coverage | Agent Manifest |
|---|---|---|---|---|---|
| 1 | System Prompt | Agent persona, behavioral boundaries, safety constraints | Prompt injection silently redefines the agent's goals | None - cleartext in memory | Full binding |
| 2 | Policy Bundle | Cedar/YAML/Rego governance rules; allow/deny decisions | Policy swap grants unapproved permissions silently | AGT + cMCP (software hash) | Hardware-sealed |
| 3 | Tool Manifest | Tool schemas, capability declarations, endpoint bindings | Schema extension silently expands agent capabilities | AGT tool scanner (software) | Full binding |
| 4 | Model Identity | Model family, version, safety alignment level, quantization | Unapproved version may lack safety training | None - operator asserted | Full binding |
| 5 | RAG Corpus | Knowledge base identity, version, ingestion policy | Corpus poisoning changes outputs without touching policy | None - no standard | Merkle root |
| 6 | Memory Baseline | Approved memory state for long-running agents | Memory drift corrupts behavior across sessions undetected | None - no standard | Snapshot hash |
| 7 | Decision Trace | Hardware-signed reasoning record per invocation | No post-hoc accountability for high-stakes decisions | AGT audit (software-signed) | TEE-signed |
| 8 | A2A Delegation | Agent-to-agent trust chain; delegated scope constraints | Orchestrator spoofing; scope laundering across delegation hops | None - no standard | Chain binding |
| 9 | Supply Chain | Container manifest; SLSA provenance; dependency SBOMs | Compromised dependency runs as approved binary | SLSA (build-time only) | Runtime measure |
| 10 | HITL Approvals | Human oversight records with identity and timestamp | EU AI Act Art. 14 violation; no accountability chain | None - no standard | Full binding |

## 2. Specification Overview

### 2.1 Design Principles

The Agent Manifest specification is designed around five principles:

**P1 - Tamper-evidence over tamper-resistance**

The manifest does not prevent tampering by making changes difficult. It makes tampering detectable by a third party who holds the manifest and compares it to a hardware attestation report. Any change to any bound artifact produces a measurement mismatch. Detection is cryptographic, not procedural.

**P2 - Independence from operator trust**

A verifying party must be able to confirm manifest integrity without trusting the operator who produced it. This requires hardware-rooted attestation (TEE measurement) for the binding layer, and a trust root that is not controlled by the entity being attested. a TEE-anchored attestation service provides this root; the specification defines the protocol for independent verification.

**P3 - Composability with existing standards**

The manifest does not replace SPIFFE/SPIRE, SLSA, SBOMs, or MCP. It composes with them. Agent identity uses SPIFFE SVIDs. Supply chain provenance uses SLSA attestation and CycloneDX SBOMs. Tool identity uses MCP's tool descriptor schema extended with a manifest binding. Policy identity uses AGT's Cedar bundle format. The manifest is the envelope that binds all of these into a single verifiable artifact.

**P4 - Minimal footprint, maximal verifiability**

The manifest stores hashes and identifiers, not content. The system prompt hash is bound; the system prompt itself is not stored in the manifest. This keeps manifests small, portable, and privacy-preserving, while ensuring that any change to any artifact breaks the hash binding and is therefore detectable.

**P5 - Protocol agnosticism with MCP as the reference implementation** <!-- CHANGED: F-04/F-05 - removed claim that A2A tool descriptors "replace" MCP tool descriptors; delegation chain is an original design with no current A2A dependency -->

The manifest is defined for any agent communication protocol. The reference implementation targets MCP because it is currently the dominant agentic wire protocol. The delegation chain cryptographic layer is protocol-agnostic by design. When A2A publishes a stable tool descriptor schema, the `tool_manifest` binding will be extended to support it; until then, field names in section 3.2.3 use MCP terminology as the reference implementation, with protocol-agnostic equivalents noted.

### 2.2 Manifest Lifecycle

An Agent Manifest is created once per agent deployment, updated when any bound artifact changes, and verified at every trust boundary crossing. The lifecycle has five phases:

| Phase | Trigger | Actor | Output |
|---|---|---|---|
| 1. Authoring | Agent deployment configuration complete | Agent developer / platform team | Unsigned draft manifest (JSON-LD) |
| 2. Signing | Human security reviewer approves configuration | Security officer / CISO delegate | Signed manifest (JWS with Ed25519 or ML-DSA-65) |
| 3. Attestation | Agent workload launches inside TEE | the Confidential Runtime | TEE attestation report binding manifest hash to hardware measurements |
| 4. Verification | Agent crosses a trust boundary (tool call, delegation, audit) | Relying party (MCP server, auditor, regulator) | Verification result: VALID \| MISMATCH \| EXPIRED \| REVOKED \| INCOMPATIBLE_VERSION |
| 5. Revocation | Any bound artifact changes, compromise detected, or TTL expires | Agent owner or the revocation service | Revocation record published to transparency log |

<!-- CHANGED: SPEC-01/F-14 - added authoring and update protocol rules, immutability rule, version negotiation -->

**Authoring and Update Protocol**

The `manifest_id` field is immutable per issuance. Any change to any signed field MUST produce a new manifest document with a new UUID v7 `manifest_id`. A `previous_manifest_id` field MAY be set in the new manifest to establish audit continuity. There is no in-place update mechanism - every change produces a new manifest.

Two update paths are defined:

- **Full re-issuance**: A new UUID v7, a new TEE attestation run, and a new transparency log entry. Required when any artifact binding changes, the signing key rotates, or the manifest expires.
- **Artifact-only refresh**: Used only for `memory_baseline.snapshot_hash` renewal within the same `ttl_seconds` window. The manifest is re-signed but the TEE attestation need not be re-run if no other artifact has changed. This path is NOT available for any other artifact.

**Version Negotiation**

A verifying party MUST inspect the `version` field before processing any other field. If the verifying party does not support the declared version, it MUST return a verification result of `INCOMPATIBLE_VERSION` and MUST NOT return `VALID` or `MISMATCH`. A verifying party that supports version N MUST NOT process a manifest with version greater than N - forward compatibility is not guaranteed across versions. Manifest producers MUST set `version` to the lowest spec version whose features they use. An optional `min_verifier_version` field (type: string, semantic version) MAY be set by the manifest author to signal that a minimum verifier version is required to correctly process the manifest.

**Key Rotation**

When a manifest signing key is rotated, the following protocol applies: (1) a new manifest MUST be issued signed by the successor key; (2) the new manifest MUST reference the previous manifest's transparency log entry in a `prior_transparency_log_entry` field; (3) the old manifest MUST be revoked upon rotation completion; (4) a `key_rotation` event type MUST be published to the transparency log. Verifiers traversing the rotation chain confirm continuity by checking that each successor manifest's `prior_transparency_log_entry` references a valid, previously-VALID manifest for the same `agent_id`. <!-- CHANGED: CRYPTO-009 - added key rotation protocol -->

### 2.3 Canonical Serialization <!-- CHANGED: CRYPTO-001/SPEC-13 - new normative section mandating RFC 8785 -->

All canonical JSON serialization in this specification uses RFC 8785 (JSON Canonicalization Scheme, JCS). This applies without exception to:

- Manifest signature pre-image computation (section 3.6)
- Per-artifact hash inputs for text artifacts
- `manifest_hash_in_report` pre-image (section 3.3)
- Memory snapshot hash input (section 3.2.6)
- Evidence pack hash (section 5.2)
- All Merkle tree leaf computations involving JSON content

The `@context` and `@type` JSON-LD fields are treated as ordinary JSON fields for canonicalization purposes. Full JSON-LD RDF dataset normalization (RDNA/GPN-09) is NOT used and MUST NOT be used as a substitute for JCS - the two algorithms produce different canonical forms. Implementations MUST reject manifests where the signature does not verify under RFC 8785 canonicalization.

**Test vector**: The object `{"b":2,"a":1}` canonicalizes under RFC 8785 to the UTF-8 byte sequence `{"a":1,"b":2}` (lexicographic key order, no insignificant whitespace). Its SHA-256 is `43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777`. Implementations MUST reproduce this value.

**Null-valued optional fields** MUST be omitted from the canonical form rather than included with a `null` value, unless this specification explicitly states a field is required and may be null (e.g., `model_hash` when `deployment_type` is `api`).

**SHAKE-256 output length**: For all artifact hash fields in the post-quantum profile, SHAKE-256 output length MUST be 256 bits (32 bytes), producing a 64-character lowercase hexadecimal string. SHAKE-256 hash values MUST be prefixed with `shake256:` in field values to distinguish them from SHA-256 hashes. <!-- CHANGED: SCHEMA F-05 - fixed SHAKE-256 output length ambiguity -->


### 2.4 Version Negotiation <!-- CHANGED: closes #45 -->

Manifest producers and verifiers negotiate spec compatibility using the `version` field in the manifest and the `spec_version` field in VerificationResult.

**Producer requirements:**
- MUST set `version` to the spec version used for manifest construction (e.g., `"0.1"`).
- MUST NOT produce fields defined only in later spec versions when targeting an older verifier.

**Verifier requirements:**
- MUST check `version` before verifying. If the version is unsupported, MUST return `INCOMPATIBLE_VERSION` rather than silently misinterpreting fields.
- SHOULD support at least the current and one prior minor version.

**Compatibility matrix:**

| Producer version | Verifier supports | Result |
|-----------------|-------------------|--------|
| 0.1 | 0.1 | VALID (if artifacts match) |
| 0.2 | 0.1 | INCOMPATIBLE_VERSION |
| 0.1 | 0.2 | VALID (0.2 verifiers MUST be backward-compatible with 0.1 manifests) |

## 3. Data Model

### 3.1 Top-Level Schema

An Agent Manifest is a JSON-LD document conforming to the following schema. All hash fields use SHA-256 unless the implementation has opted into the post-quantum profile, in which case SHAKE-256 is used (see section 2.3 for output length). Hash field values MUST conform to the pattern `^(sha256|shake256):[0-9a-f]{64}$`. Signature fields use Ed25519 for standard deployments and ML-DSA-65 for post-quantum deployments.

<!-- CHANGED: F-06 - @context URL changed from agentmanifest.opaque.co to vendor-neutral domain -->
<!-- CHANGED: F-04/SPEC-13 - added note on UUID v7 requirement per RFC 9562 -->
<!-- CHANGED: SCHEMA F-02 - added field-level cardinality markers; SCHEMA F-03 - added normative TTL constraints; SCHEMA F-04 - added UUID v7 citation; SCHEMA F-14 - added min_verifier_version -->

```json
{
  "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
  "@type": "AgentManifest",
  "manifest_id": "<string, UUID v7 per RFC 9562 - REQUIRED>",
  "previous_manifest_id": "<string, UUID v7 - OPTIONAL, set on re-issuance>",
  "agent_id": "<string, SPIFFE URI - REQUIRED>",
  "version": "<string - REQUIRED, set to '0.1'>",
  "min_verifier_version": "<string, semantic version - OPTIONAL>",
  "issued_at": "<string, ISO 8601 UTC - REQUIRED>",
  "expires_at": "<string, ISO 8601 UTC - REQUIRED, default issued_at + 90 days>",
  "issuer": "<string, SPIFFE URI of signing authority - REQUIRED>",
  "crypto_profile": "<string, 'standard' | 'post-quantum' - REQUIRED>",
  "artifacts": "<object - REQUIRED, see section 3.2>",
  "attestation": "<object - REQUIRED for Level 1+, see section 3.3>",
  "delegation_chain": "<array - REQUIRED if agent is spawned by another agent, see section 3.4>",
  "hitl_record": "<object - REQUIRED if any policy mandates HITL, see section 3.5>",
  "signature": "<object - REQUIRED, see section 3.6>",
  "transparency_log_entry": "<object - REQUIRED for production, see section 3.6>"
}
```

**Field cardinality table**

| Field | Type | Cardinality | Constraint |
|---|---|---|---|
| `manifest_id` | string (UUID v7, RFC 9562) | REQUIRED | Version nibble MUST be 7. Canonical 8-4-4-4-12 hyphenated lowercase hex. |
| `previous_manifest_id` | string (UUID v7, RFC 9562) | OPTIONAL | Set on re-issuance to establish audit chain continuity. |
| `agent_id` | string (SPIFFE URI) | REQUIRED | Trust domain lowercase `[a-z0-9._-]`; path segments `[a-zA-Z0-9._-]`. URI MUST NOT exceed 2048 bytes. |
| `version` | string | REQUIRED | MUST be `"0.1"` for this specification version. |
| `min_verifier_version` | string (semver) | OPTIONAL | Minimum verifier version required to correctly process this manifest. |
| `issued_at` | string (ISO 8601 UTC) | REQUIRED | |
| `expires_at` | string (ISO 8601 UTC) | REQUIRED | Default: `issued_at` + 90 days. MUST NOT be more than 365 days after `issued_at` for Level 1+. MUST NOT be less than 1 hour after `issued_at`. |
| `issuer` | string (SPIFFE URI) | REQUIRED | |
| `crypto_profile` | string enum | REQUIRED | `"standard"` or `"post-quantum"`. |
| `artifacts` | object | REQUIRED | |
| `attestation` | object | REQUIRED for Level 1+ | MUST be omitted (not null) at Level 0. |
| `delegation_chain` | array | CONDITIONALLY REQUIRED | REQUIRED when agent is spawned by another agent. Empty array is invalid - omit the field entirely if no delegation. |
| `hitl_record` | object | CONDITIONALLY REQUIRED | REQUIRED when any bound policy mandates human-in-the-loop approval. |
| `signature` | object | REQUIRED | |
| `transparency_log_entry` | object | REQUIRED for production (Level 1+) | Separate from `signature`; populated after log submission. |

<!-- CHANGED: SCHEMA F-03 - normative TTL rule -->
The `expires_at` field MUST be present. If omitted by the manifest author, implementations MUST default to `issued_at` + 90 days. The `expires_at` value MUST NOT be more than 365 days after `issued_at` for Level 1 and above deployments. The `expires_at` value MUST NOT be less than 1 hour after `issued_at`. A verifying party MUST reject a manifest whose `expires_at` is in the past at the time of verification.

<!-- CHANGED: SCHEMA F-04 - normative UUID v7 rule -->
All fields annotated as UUID v7 MUST conform to RFC 9562 Section 5.7. The string representation MUST use the canonical 8-4-4-4-12 hyphenated lowercase hexadecimal format. The version nibble MUST be 7 (binary 0111). Implementations MUST reject UUID fields whose version nibble is not 7.

<!-- CHANGED: F-01 - SPIFFE URI path note -->
The `agent_id` path structure `/agent/<name>/<instance>` shown in examples is a convention, not a requirement. Trust domain must be lowercase `[a-z0-9._-]`; path segments may use `[a-zA-Z0-9._-]`. UUID v7 instance identifiers (hyphens permitted in path segments) are valid. Example: `spiffe://example.opaque.co/agent/payments-processor/01926b4c-1234-7abc-9def-000000000001`.

<!-- CHANGED: SCHEMA F-15/@context - normative note on provisional URL -->
The `@context` URL `https://agentmanifest.agentrust.io/v0.1/context.json` is provisional for the v0.1 draft period. The AAIF working group will assign the canonical URL prior to v1.0 ratification. Implementations MUST support the canonical AAIF URL when it is assigned, and SHOULD support the v0.1 draft URL for backward compatibility with pre-ratification manifests.

<!-- CHANGED: SCHEMA F-19 - normative artifact-to-field mapping table -->
**Artifact-to-field mapping** (for Level 2 "all 10 artifacts bound" conformance):

| Artifact # | Artifact Name | JSON field location |
|---|---|---|
| 1 | System Prompt | `artifacts.system_prompt` |
| 2 | Policy Bundle | `artifacts.policy_bundle` |
| 3 | Tool Manifest | `artifacts.tool_manifest` |
| 4 | Model Identity | `artifacts.model_identity` |
| 5 | RAG Corpus | `artifacts.rag_corpus` |
| 6 | Memory Baseline | `artifacts.memory_baseline` |
| 7 | Decision Trace | `artifacts.decision_trace` |
| 8 | A2A Delegation | `delegation_chain` (top-level array) |
| 9 | Supply Chain | `artifacts.supply_chain` |
| 10 | HITL Approvals | `hitl_record` (top-level object) |

For Level 2, "all 10 artifacts bound" means artifacts 1-7 and 9 MUST be present in `artifacts`; `delegation_chain` MUST be a non-empty array if the agent is spawned by another agent; and `hitl_record.required` MUST be `true` with at least one approval present.

### 3.2 Artifact Bindings

Each artifact is represented by a binding object containing the artifact's cryptographic hash, its identifier or locator, the binding timestamp, and optionally a structured descriptor. The binding object is what appears in the manifest; the artifact itself is stored separately and referenced by hash.

#### 3.2.1 System Prompt Binding

```json
"system_prompt": {
  "hash": "sha256:<64-hex-chars>  -- REQUIRED",
  "hash_algorithm": "SHA-256 | SHAKE-256  -- REQUIRED",
  "version": "<semantic version or timestamp>  -- REQUIRED",
  "classification": "public | internal | confidential | restricted  -- REQUIRED",
  "language": "<BCP 47 language tag>  -- OPTIONAL",
  "safety_level": "<operator-defined safety tier>  -- OPTIONAL",
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

The system prompt hash binds the complete byte sequence of the prompt as delivered to the model. Any modification - including whitespace changes, character encoding changes, or appended injections - produces a different hash and invalidates the manifest. Implementations MUST hash the prompt as a UTF-8 byte sequence with no BOM, normalized to NFC.

#### 3.2.2 Policy Bundle Binding

<!-- CHANGED: SCHEMA F-18 - added composite bundle hash computation rule; added AGT scope identifier format note -->

```json
"policy_bundle": {
  "hash": "sha256:<64-hex-chars>  -- REQUIRED",
  "policy_language": "cedar | rego | yaml-agt | composite  -- REQUIRED",
  "version": "<semantic version>  -- REQUIRED",
  "enforcement_mode": "enforce | advisory | audit-only  -- REQUIRED",
  "scope": "<array of AGT policy scope identifiers>  -- OPTIONAL",
  "agt_version": "<AGT version that produced this bundle>  -- CONDITIONALLY REQUIRED: REQUIRED when policy_language is yaml-agt or composite>",
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

The policy bundle hash covers the complete Cedar policy set, including all policy templates and entity schemas. The `enforcement_mode` field is normative - a verifying party MUST reject a manifest whose `enforcement_mode` is `advisory` when the context requires `enforce`. This field aligns with cMCP's `enforcement_mode` attestation field.

For `policy_language: composite`, the `hash` field MUST be a Merkle root over the hashes of each sub-bundle, sorted by policy language identifier in lexicographic order (`cedar`, `rego`, `yaml-agt`). Each sub-bundle MUST be hashed independently using the same hash algorithm as the manifest. The `agt_version` field MUST reference the AGT version used to assemble the composite bundle, even if individual sub-bundles were produced by other tools.

AGT policy scope identifiers use the form `<namespace>:<resource-type>:<action>`, e.g., `finance:ledger:write`. For the full scope identifier registry, refer to the AGT specification.

#### 3.2.3 Tool Manifest Binding

<!-- CHANGED: F-05 - renamed MCP-specific fields to protocol-agnostic equivalents with MCP mapping note; CRYPTO-002/SPEC-03 - fixed catalog_hash to commit to both schema and description per tool; SPEC-04 - added dynamic registration enforcement note; SCHEMA F-07 - fixed allow_dynamic_registration boolean type and rug_pull_policy definitions; SCHEMA F-05 - egress_destinations none removed from array -->

> **Protocol note**: Field values in this section use MCP terminology as the reference implementation. For other protocols, `tool_name` maps to the protocol-native tool identifier and `endpoint_id` maps to the protocol-native server identity. The `rug_pull_policy` field describes a class of attack applicable to any protocol mechanism by which a tool endpoint signals a capability change - not only MCP `notifications/tools/list_changed`.

```json
"tool_manifest": {
  "catalog_hash": "sha256:<64-hex-chars>  -- REQUIRED",
  "tools": [
    {
      "tool_id": "<reverse-domain tool identifier>  -- REQUIRED",
      "tool_name": "<protocol-native tool name, e.g. MCP tool name>  -- REQUIRED",
      "endpoint_id": "<SPIFFE URI of tool endpoint server, e.g. MCP server>  -- REQUIRED",
      "schema_hash": "sha256:<64-hex-chars>  -- REQUIRED",
      "description_hash": "sha256:<64-hex-chars>  -- REQUIRED",
      "version": "<semantic version>  -- REQUIRED",
      "permission_scope": "<Cedar entity type>  -- OPTIONAL",
      "egress_destinations": ["<FQDN | IP CIDR>  -- OPTIONAL, empty array means no external egress permitted"]
    }
  ],
  "allow_dynamic_registration": "<boolean -- REQUIRED, default false>",
  "rug_pull_policy": "deny-and-alert | deny-and-hold | require-reapproval  -- REQUIRED",
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

**`catalog_hash` construction** <!-- CHANGED: CRYPTO-002/SPEC-03 - catalog_hash now commits to both schema_hash and description_hash -->

The `catalog_hash` is a Merkle root over per-tool leaf hashes. Each leaf is computed as:

```
leaf_hash(tool) = SHA-256(0x00 || tool_id_utf8_bytes || 0x00 || schema_hash_bytes || description_hash_bytes)
```

Tools are sorted lexicographically by `tool_id` before tree construction. Interior nodes use `SHA-256(0x01 || left_child_hash || right_child_hash)` per the RFC 9162 domain-separated construction (see section 4.1). This construction ensures that any mutation of either a tool's schema or its description - the primary MCP tool poisoning attack vector - breaks the `catalog_hash` Merkle root.

A test vector for a two-tool catalog MUST be published in Appendix D of the reference implementation.

**`allow_dynamic_registration`** MUST be `false` for Level 1+ deployments unless `hitl_record.approvals` contains an approval with `approved_scope.artifacts` including `"tool_manifest"` and an `approval_duration_seconds` covering the dynamic registration window. Any protocol mechanism by which a tool endpoint signals a capability change that adds a tool not in the approved catalog MUST trigger a `rug_pull_policy` action and emit a signed `RUG_PULL_DETECTED` evidence event to the audit log.

**`rug_pull_policy` action definitions**: <!-- CHANGED: SPEC-04 - defined all three policy actions precisely -->
- `deny-and-alert`: Reject the new tool registration. Continue serving previously approved tools. Emit a `RUG_PULL_DETECTED` evidence event (see section 3.2.3.1) to the audit log.
- `deny-and-hold`: Same as `deny-and-alert`, plus suspend all tool calls until an operator explicitly acknowledges the event. Queue depth is implementation-defined; calls that exceed the queue MUST be rejected with an error surfaced to the agent.
- `require-reapproval`: Same as `deny-and-hold`, plus initiate the HITL re-approval flow defined in section 3.5.

Tool removal events (where a previously approved tool disappears from the catalog) MUST also trigger the configured `rug_pull_policy` action, as removal of a logging or auditing tool is itself a security event.

**`egress_destinations`**: An empty array `[]` is the representation for no external egress permitted. The value `"none"` MUST NOT appear as an array element. <!-- CHANGED: SCHEMA F-07 - removed none from array -->

##### 3.2.3.1 Dynamic Tool Registration Enforcement <!-- CHANGED: SPEC-04 - new normative subsection -->

Enforcement responsibility is assigned as follows:

- **Phase 2 (cMCP Runtime) deployments**: The cMCP Runtime is the enforcement actor for `rug_pull_policy`. It intercepts tool capability change notifications before they reach the agent.
- **Level 0/1 deployments without cMCP**: The agent SDK is the enforcement actor. SDK implementations MUST intercept tool capability change events from the underlying protocol transport.

The `RUG_PULL_DETECTED` evidence event is a structured record conforming to a subset of the TRACE envelope (section 6.3.2) with the following additional fields:

```json
{
  "event_type": "RUG_PULL_DETECTED",
  "affected_tool_id": "<tool_id of added or removed tool>",
  "change_type": "addition | removal",
  "policy_action": "<deny-and-alert | deny-and-hold | require-reapproval>",
  "detected_at": "<ISO 8601 UTC>",
  "manifest_id": "<UUID v7 of the current manifest>"
}
```

#### 3.2.4 Model Identity Binding

<!-- CHANGED: CRYPTO-008 - added model_attestation_type field; SCHEMA F-08 - fixed model_hash null annotation, added third-party-api deployment_type, added capability_level note -->

```json
"model_identity": {
  "provider": "<model provider identifier>  -- REQUIRED",
  "model_id": "<provider-scoped model identifier>  -- REQUIRED",
  "version": "<model version or hash>  -- REQUIRED",
  "capability_level": "<provider-defined capability tier>  -- OPTIONAL",
  "safety_alignment_version": "<RLHF/Constitutional AI version>  -- OPTIONAL",
  "quantization": "none | int8 | int4 | fp8 | <other>  -- OPTIONAL",
  "deployment_type": "api | local | confidential-inference | third-party-api  -- REQUIRED",
  "model_hash": "sha256:<64-hex-chars> | null  -- CONDITIONALLY REQUIRED",
  "model_attestation_type": "hash-bound | provider-asserted  -- REQUIRED",
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

`model_hash` is REQUIRED when `deployment_type` is `local` or `confidential-inference` and MUST match the measured binary. `model_hash` MUST be `null` when `deployment_type` is `api` or `third-party-api`. A model version mismatch between the manifest and the running inference service MUST invalidate the manifest.

`model_attestation_type` MUST be set to `hash-bound` when `model_hash` is non-null (local or confidential-inference deployments), and `provider-asserted` when `model_hash` is null (API deployments). Verification results (section 5.2) MUST return `model_identity: "PROVIDER_ASSERTED"` rather than `"MATCH"` when `model_attestation_type` is `provider-asserted`, so that verifiers have an explicit signal that this is a weaker, operator-asserted binding rather than a hardware-rooted one. See section 9.1 for implications on EU AI Act Art. 13 satisfaction.

`deployment_type` value `"third-party-api"` covers API models not served directly by the declared provider (e.g., a model accessed via an intermediary cloud API gateway).

`capability_level` and `safety_alignment_version` are informational fields. For Anthropic models, `capability_level` SHOULD use the provider's published tier identifier (e.g., `"claude-tier-3"`). These fields MUST NOT be used as a security boundary. Verifiers MUST NOT use them as a substitute for `model_hash` or `model_attestation_type`.

#### 3.2.5 RAG Corpus Binding

<!-- CHANGED: SPEC-02 - added normative Merkle tree construction subsection; SCHEMA F-17 - added normative scan result rules -->

```json
"rag_corpus": {
  "corpus_id": "<operator-assigned stable identifier>  -- REQUIRED",
  "merkle_root": "sha256:<64-hex-chars>  -- REQUIRED",
  "document_count": "<integer>  -- REQUIRED",
  "ingestion_policy_hash": "sha256:<64-hex-chars>  -- REQUIRED",
  "vector_store": "<vector store type and version>  -- REQUIRED",
  "embedding_model": "<embedding model identifier>  -- REQUIRED",
  "last_updated": "<ISO 8601 UTC>  -- REQUIRED",
  "poisoning_scan": {
    "scanner_version": "<scanner tool name and semver, format: tool-name/x.y.z>  -- REQUIRED for Level 1+",
    "scanned_at": "<ISO 8601 UTC>  -- REQUIRED for Level 1+",
    "result": "clean | flagged | not-scanned  -- REQUIRED"
  },
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

##### 3.2.5.1 Corpus Merkle Tree Construction <!-- CHANGED: SPEC-02 - new normative subsection -->

The document unit for corpus hashing is the ingestion record as stored in the vector store, defined as the tuple (`document_id`, `content_bytes`). Metadata is excluded from the leaf hash to avoid invalidating the corpus binding on metadata-only changes (e.g., tag updates); instead, the `ingestion_policy_hash` covers the policy governing metadata.

Each leaf hash is computed as:

```
leaf_hash(doc) = SHA-256(0x00 || document_id_utf8_bytes || 0x00 || content_bytes)
```

Leaves are sorted lexicographically by their leaf hash value before tree construction. The tree uses a left-balanced binary structure with domain-separated interior nodes:

```
node_hash = SHA-256(0x01 || left_child_hash || right_child_hash)
```

This construction is consistent with RFC 9162 Certificate Transparency (see also section 4.1 on domain separation). The `merkle_root` field value MUST use the `sha256:` prefix format.

**Poisoning scan rules**: <!-- CHANGED: SCHEMA F-17 -->
- A manifest with `poisoning_scan.result: flagged` MUST NOT be issued as VALID. The manifest MUST be held in `INCOMPLETE` state until flagged documents are removed and a clean scan completed.
- For Level 1 conformance and above, `poisoning_scan.result: not-scanned` is NOT permitted. The corpus MUST be scanned before the manifest is signed.
- For Level 0, `not-scanned` is permitted but MUST surface as a warning in the verification result.
- `scanner_version` MUST include the scanner tool name and semantic version string in the format `"<tool-name>/<semver>"` (e.g., `"lakera-scan/1.4.2"`). When the AAIF scanner registry is established in v0.2, implementations SHOULD reference a registered scanner identifier.

#### 3.2.6 Memory Baseline Binding

<!-- CHANGED: SPEC-06 - added snapshot protocol subsection; SCHEMA F-06 - added ttl_seconds constraints, memory_type definitions, drift_policy conformance rules -->

```json
"memory_baseline": {
  "baseline_id": "<UUID v7>  -- REQUIRED",
  "snapshot_hash": "sha256:<64-hex-chars> | null  -- REQUIRED (null only when memory_type is none)",
  "memory_type": "none | session | persistent | shared  -- REQUIRED",
  "store": "<memory store type and version>  -- REQUIRED",
  "approved_at": "<ISO 8601 UTC>  -- REQUIRED",
  "ttl_seconds": "<positive integer>  -- CONDITIONALLY REQUIRED",
  "drift_policy": "deny-on-drift | alert-on-drift | log-only  -- REQUIRED",
  "shared_memory_owner": "<manifest_id of the agent holding the authoritative snapshot>  -- CONDITIONALLY REQUIRED",
  "check_interval_seconds": "<positive integer>  -- OPTIONAL",
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

**Memory type definitions**:
- `none`: The agent has no memory. `ttl_seconds` SHOULD be omitted; `snapshot_hash` MUST be null.
- `session`: Memory scoped to a single conversation session. Session memory is exempt from drift detection within a session boundary - `snapshot_hash` represents the approved initial state only.
- `persistent`: Memory that persists across sessions. `snapshot_hash` represents the last approved memory checkpoint.
- `shared`: Memory state shared across multiple instances of the same agent version, identified by the same `baseline_id`. Each instance MUST reference the same `snapshot_hash`. A designated owner agent MUST hold the authoritative `snapshot_hash`; other agents MUST reference the owner's `manifest_id` in `shared_memory_owner`.

**`ttl_seconds`** MUST be a positive integer when present. Minimum value: 3600 (1 hour). Maximum value: 7776000 (90 days). REQUIRED when `memory_type` is `persistent` or `shared`.

**`drift_policy`** conformance: For Level 2 conformance, `drift_policy` MUST be `deny-on-drift` or `alert-on-drift`. `log-only` is permitted only at Level 0 and Level 1.

##### 3.2.6.1 Memory Snapshot and Drift Protocol <!-- CHANGED: SPEC-06 - new normative subsection -->

`snapshot_hash` is the SHA-256 of the RFC 8785 canonical JSON serialization of the complete memory store key-value map, with keys sorted lexicographically. For non-JSON memory backends (e.g., Redis key-value stores), the implementation MUST export the complete store state as a JSON object before applying RFC 8785 canonicalization.

Drift checks are performed at agent startup (comparing the running store against `snapshot_hash`) and at intervals defined by `check_interval_seconds` if set. Session memory is exempt from drift detection within a session boundary.

For `drift_policy` action definitions:
- `deny-on-drift`: Reject all tool calls and agent actions upon drift detection. Emit a `MEMORY_DRIFT_DETECTED` evidence event to the audit log. Require manual operator acknowledgment before resuming.
- `alert-on-drift`: Emit a `MEMORY_DRIFT_DETECTED` evidence event. Continue operation but surface the alert in every verification result until acknowledged.
- `log-only`: Record the drift in the audit log. No operational impact.


#### 3.2.7 Decision Trace Binding <!-- CHANGED: added missing artifact #7 schema block -->

```json
"decision_trace": {
  "trace_type": "hash-chained | merkle-log",
  "audit_chain_root": "sha256:<64-hex-chars>",
  "audit_chain_uri": "<HTTPS URI to audit log endpoint>",
  "signing_key_id": "<TEE-sealed key identifier>",
  "audit_key_sealed": true,
  "first_entry_at": "<ISO 8601 UTC>",
  "last_entry_at": "<ISO 8601 UTC>",
  "entry_count": "<integer>",
  "bound_at": "<ISO 8601 UTC>"
}
```

| Field | Cardinality | Notes |
|-------|-------------|-------|
| `trace_type` | REQUIRED | `hash-chained` for sequential ECDSA-P256 chains; `merkle-log` for tree-based logs |
| `audit_chain_root` | REQUIRED | SHA-256 root of the entire audit chain as of manifest signing time |
| `audit_chain_uri` | REQUIRED | HTTPS endpoint where the full audit chain can be fetched for verification |
| `signing_key_id` | REQUIRED | Identifier of the TEE-sealed key that signs each audit entry |
| `audit_key_sealed` | REQUIRED | MUST be `true` for Level 1+ conformance. A value of `false` indicates a software-signed chain and MUST be treated as software-attested only |
| `first_entry_at` | REQUIRED | Timestamp of the first entry in the chain; used to detect chain truncation |
| `last_entry_at` | REQUIRED | Timestamp of the most recent entry at manifest signing time |
| `entry_count` | OPTIONAL | Total number of entries in the chain; allows verifiers to detect entry deletion |
| `bound_at` | REQUIRED | When this binding was captured |

The `audit_chain_root` in this binding MUST match the `audit_chain_root` field in the cMCP attestation report (Section 6.2). A mismatch between these two values indicates the manifest was signed against a different audit chain than the one currently running, which MUST cause verification to return MISMATCH.

`audit_key_sealed: false` does not invalidate the manifest but MUST be surfaced in the verification result as a warning. A verifying party that requires hardware-rooted evidence (e.g., Level 1+ conformance, regulatory audit) MUST treat `audit_key_sealed: false` as equivalent to NOT_BOUND for attestation purposes.

#### 3.2.8 Supply Chain Binding

<!-- CHANGED: F-03 - replaced slsa_provenance block with verifiable fields aligned to DSSE/in-toto; SCHEMA F-16/F-07 - added serial_number to sbom block, renamed version to schema_version; SCHEMA F-07 - fixed phase2_attested boolean type -->

```json
"supply_chain": {
  "container_image_digest": "sha256:<64-hex-chars>  -- REQUIRED",
  "base_image_digest": "sha256:<64-hex-chars>  -- OPTIONAL",
  "slsa_provenance": {
    "builder_id": "<URI: runDetails.builder.id from the SLSA attestation>  -- REQUIRED",
    "subject_digest": "sha256:<64-hex-chars>  -- REQUIRED, must match container_image_digest>",
    "provenance_uri": "<URI to the DSSE envelope or OCI referrer>  -- REQUIRED",
    "rekor_entry_id": "<Rekor entry UUID for signature verification>  -- REQUIRED for Level 2+",
    "declared_level": "1 | 2 | 3 | 4  -- OPTIONAL, non-normative operator declaration"
  },
  "sbom": {
    "format": "cyclonedx | spdx  -- REQUIRED",
    "schema_version": "<SBOM specification schema version, e.g. CycloneDX 1.6 or SPDX 2.3>  -- REQUIRED",
    "document_id": "<CycloneDX serialNumber URN or SPDX documentNamespace URI>  -- REQUIRED",
    "sbom_hash": "sha256:<64-hex-chars>  -- REQUIRED",
    "sbom_uri": "<URI to SBOM document>  -- REQUIRED"
  },
  "mcp_servers": [
    {
      "server_id": "<SPIFFE URI>  -- REQUIRED",
      "image_digest": "sha256:<64-hex-chars>  -- REQUIRED",
      "slsa_level": "1 | 2 | 3 | 4  -- REQUIRED",
      "phase2_attested": "<boolean>  -- REQUIRED",
      "sbom": {
        "format": "cyclonedx | spdx  -- OPTIONAL",
        "schema_version": "<SBOM specification schema version>  -- OPTIONAL",
        "document_id": "<CycloneDX serialNumber URN or SPDX documentNamespace URI>  -- OPTIONAL",
        "sbom_hash": "sha256:<64-hex-chars>  -- OPTIONAL",
        "sbom_uri": "<URI to SBOM document>  -- OPTIONAL"
      }
    }
  ],
  "bound_at": "<ISO 8601 UTC>  -- REQUIRED"
}
```

The `container_image_digest` is the primary supply chain binding for the agent runtime. It MUST match the hardware measurement in the TEE attestation report. The `mcp_servers` array binds the supply chain identity of each connected MCP server - `phase2_attested` (JSON boolean) indicates whether the server is running inside a TEE with its own hardware attestation (Phase 2 / cMCP server-side).

The `slsa_provenance.declared_level` field is non-normative and represents the operator's declared SLSA level summary. The actual SLSA level is determined by the `builder_id` value in the referenced DSSE attestation envelope. Verifiers MUST fetch and validate the DSSE envelope at `provenance_uri` - the manifest binding is a pointer to the attestation, not a substitute for it.

The `sbom.document_id` field MUST be set to the `serialNumber` URN for CycloneDX format documents, or the `documentNamespace` URI for SPDX format documents. The `sbom.schema_version` field refers to the SBOM specification schema version (e.g., `"CycloneDX 1.6"`, `"SPDX 2.3"`), not a document revision number.

### 3.3 Hardware Attestation Binding

The attestation block binds the manifest to a specific TEE hardware measurement. It is produced by the the Confidential Runtime at agent launch time and is not part of the draft manifest - it is appended after the TEE measurement is complete.

<!-- CHANGED: SPEC-08 - added Platform Attestation Profiles subsection; SPEC-09 - clarified manifest_hash_in_report pre-image; SCHEMA F-09 - expanded platform enum to include arm-cca and google-confidential-space; CRYPTO-010 - added RATS reference and verification protocol note -->

```json
"attestation": {
  "platform": "amd-sev-snp | intel-tdx | nvidia-blackwell | aws-nitro | arm-cca | google-confidential-space  -- REQUIRED",
  "tee_version": "<platform firmware version>  -- REQUIRED",
  "measurement": "<platform-specific launch measurement - see section 3.3.1 for per-platform format>  -- REQUIRED",
  "manifest_hash_in_report": "sha256:<64-hex-chars>  -- REQUIRED",
  "policy_bundle_hash": "sha256:<64-hex-chars>  -- REQUIRED",
  "enforcement_mode": "enforce | advisory | audit-only  -- REQUIRED",
  "audit_chain_root": "sha256:<64-hex-chars>  -- REQUIRED for Level 1+",
  "audit_key_sealed": "<boolean>  -- REQUIRED",
  "container_image_digest": "sha256:<64-hex-chars>  -- REQUIRED",
  "report_timestamp": "<ISO 8601 UTC>  -- REQUIRED",
  "report_uri": "<URI to full platform attestation report>  -- REQUIRED",
  "attestation_service": {
    "service_id": "<SPIFFE URI of the attestation service>  -- REQUIRED",
    "service_measurement": "<TEE measurement of attestation service itself>  -- REQUIRED",
    "verification_endpoint": "<HTTPS URI>  -- REQUIRED"
  }
}
```

**`manifest_hash_in_report` pre-image** <!-- CHANGED: SPEC-09 - normative pre-image definition -->

The `manifest_hash_in_report` pre-image is the RFC 8785 canonical JSON serialization of the full manifest document including the `signature` block and excluding only the `attestation` block. The `attestation` key MUST NOT be present in the pre-image document. The `transparency_log_entry` key MUST also be absent from the pre-image (it is populated after log submission). The hash MUST be computed over the UTF-8 encoding of this canonical form with no BOM.

The `audit_key_sealed` field (JSON boolean) MUST be `true` for production deployments. It indicates that the audit log signing key was generated inside the TEE and has never been exported to operator-readable memory. A manifest with `audit_key_sealed: false` MUST be treated as software-attested and MUST NOT satisfy regulatory requirements that call for hardware-rooted evidence.

**Attestation verification protocol** <!-- CHANGED: CRYPTO-010 - RATS reference -->

The attestation service acts as a RATS Verifier in the sense of RFC 9334. For deployments where a third party wishes to verify TEE measurements independently (without trusting the attestation service as intermediary), the service MUST produce a normalized attestation result in the form of an Entity Attestation Token (EAT, per RFC 9528) derived from the raw platform report. The `report_uri` provides the raw platform report for parties wishing to perform independent verification using platform vendor SDKs (AMD `sev-snp-verify`, Intel TDX Attest SDK, etc.).

##### 3.3.1 Platform Attestation Profiles <!-- CHANGED: SPEC-08 - new normative subsection per platform -->

The following profiles define, per platform, the measurement field used to carry the `manifest_hash_in_report`, the format of the `measurement` field, and which component performs the extension.

**AMD SEV-SNP**
- `manifest_hash_in_report` is extended into the `HOST_DATA` field of the SNP attestation report (64 bytes, purpose-built for guest-supplied data). Do NOT use a PCR register for this purpose.
- `measurement` field: SHA-384 of initial guest memory pages (96 bytes, 192 lowercase hex characters).
- Extension actor: the Confidential Runtime extends `HOST_DATA` before guest launch.

**Intel TDX**
- `manifest_hash_in_report` is extended into `RTMR[1]` using `TDG.MR.RTMR.EXTEND` before any workload code runs.
- `measurement` field: MRTD value (SHA-384, 96 bytes, 192 lowercase hex characters). For deployments using multiple RTMRs, the `measurement` field MUST be a JSON object: `{"mrtd": "<hex>", "rtmr0": "<hex>", "rtmr1": "<hex>", "rtmr2": "<hex>", "rtmr3": "<hex>"}`.
- Extension actor: the Confidential Runtime performs the RTMR extension.

**AWS Nitro**
- `manifest_hash_in_report` is extended into PCR15 using `tpm2_extend` with SHA-256 bank before instance launch. PCR15 is reserved for custom measurements and MUST be used. <!-- CHANGED: instructions - PCR 15 per spec requirement -->
- `measurement` field: A JSON object of PCR index to SHA-384 hex values: `{"pcr0": "<hex>", "pcr1": "<hex>", "pcr15": "<hex>"}`. At minimum, PCR0, PCR1, and PCR15 MUST be present.
- Extension actor: Instance bootloader extends PCR15; the Confidential Runtime verifies the extension before proceeding.

**NVIDIA Blackwell**
- `manifest_hash_in_report` is embedded in the SPDM measurements report as custom measurement index `0x05` (implementation-reserved, distinct from NVIDIA firmware indices 0x00-0x04).
- `measurement` field: SPDM measurement digest as provided by the NVIDIA attestation SDK (format per NVIDIA Hopper/Blackwell attestation documentation).
- Extension actor: the Confidential Runtime writes the custom measurement index before attestation report generation.

**ARM CCA**
- `manifest_hash_in_report` is extended into the Realm Measurement Register (RMR) at index 1 using `RSI_MEASUREMENT_EXTEND` before workload execution.
- `measurement` field: Realm measurement register value (SHA-512, 64 bytes, 128 lowercase hex characters).
- Extension actor: Realm Management Monitor (RMM) applies the extension; the Confidential Runtime initiates via RSI call.

**Google Confidential Space**
- Google Confidential Space uses AMD SEV-SNP as the underlying TEE. The AMD SEV-SNP profile applies. Additionally, the `measurement` field MUST include the Confidential Space-specific `sub_mod` claims from the OIDC token issued by the Confidential Space attestation service.
- Extension actor: As per AMD SEV-SNP profile.

### 3.4 A2A Delegation Chain

<!-- CHANGED: F-04 - clarified delegation chain is original design with no A2A protocol dependency; SPEC-05 - added normative Scope Grant Semantics subsection; SCHEMA F-10 - added normative max_delegation_depth default and Cedar constraint validation rules -->

> **Standards note**: The delegation chain defined in this section is an original design in this specification with no dependency on any published A2A wire protocol standard. As of the date of this specification, no published A2A standard defines a delegation chain, scope grant format, or inter-agent trust primitive. This specification intends to align the delegation chain with A2A as that standard matures. Section 10.4 notes the relationship accurately.

When an agent is spawned by another agent in a multi-agent system, the delegating agent's identity and scope grant must be bound in the manifest. The `delegation_chain` array is ordered from root principal (human or system) to the current agent.

```json
"delegation_chain": [
  {
    "hop": "<integer, 0-indexed>  -- REQUIRED",
    "principal_type": "human | system | agent  -- REQUIRED",
    "principal_id": "<SPIFFE URI (for system or agent) | OIDC subject URI | email URI | W3C DID (for human)>  -- REQUIRED",
    "delegated_at": "<ISO 8601 UTC>  -- REQUIRED",
    "scope_grant": {
      "tools": ["<tool_id>  -- OPTIONAL"],
      "data_classifications": ["public | internal | confidential | restricted  -- OPTIONAL"],
      "max_delegation_depth": "<positive integer>  -- OPTIONAL, default 3>",
      "ttl_seconds": "<positive integer>  -- OPTIONAL",
      "constraints": ["<Cedar permit or forbid statement>  -- OPTIONAL"]
    },
    "delegation_signature": "<Ed25519 | ML-DSA-65 signature by principal>  -- REQUIRED",
    "principal_manifest_id": "<manifest_id of delegating agent, if agent>  -- CONDITIONALLY REQUIRED",
    "principal_attestation_hash": "<attestation hash of delegating agent, if attested>  -- OPTIONAL"
  }
]
```

##### 3.4.1 Scope Grant Semantics <!-- CHANGED: SPEC-05 - new normative subsection -->

Constraints are strictly restrictive - they can only narrow the scope granted at the previous hop, never extend it. The effective permission set for hop N is the intersection of the scope granted at hop N-1 and the constraints at hop N. A child agent MUST NOT use the constraint mechanism to claim permissions not granted by its parent - this structural property prevents scope laundering.

Constraints are evaluated using the Cedar entity store and schema from the `policy_bundle` bound in the root manifest of the delegation chain. Each element of `scope_grant.constraints` MUST be a syntactically complete Cedar `permit` or `forbid` statement with explicit `principal`, `action`, and `resource` slots - not a fragment. A verifier MUST reject a delegation chain where any constraint references an entity type not present in the root `policy_bundle` schema.

Verifying parties that support Cedar MUST parse and evaluate each constraint. Verifying parties that do not support Cedar MUST treat a non-empty `constraints` array as `UNVERIFIABLE` and MUST surface this in the verification result rather than treating it as `VALID`.

If `max_delegation_depth` is omitted from a `scope_grant`, verifying parties MUST apply a default value of 3. A `max_delegation_depth` of 0 means no further delegation is permitted. Verifying parties MUST count delegation hops from the root and MUST reject chains whose depth exceeds the `max_delegation_depth` of the root scope_grant.

The delegation chain is the cryptographic primitive that closes the post-hoc accountability gap - the absence of a tamper-evident proof of the full delegation chain from human principal through orchestrator to tool call. Each hop must be signed by the delegating principal's key. The `scope_grant` at each hop may only be a subset of the scope granted at the previous hop - scope laundering is structurally prevented because each hop's scope is signed by the granting agent.

### 3.5 Human-in-the-Loop Approval Records

<!-- CHANGED: REG-001 - added hitl_runtime block for Art. 14 operational oversight; F-09 - fixed approver_id to use human-attributable identity; SCHEMA F-11 - fixed required to JSON boolean, added approval_method trust ordering -->

For agents operating under EU AI Act Article 14 requirements or any policy that mandates human oversight, the `hitl_record` block captures human approval events in a cryptographically bound, non-repudiable form.

```json
"hitl_record": {
  "required": "<boolean>  -- REQUIRED",
  "approvals": [
    {
      "approval_id": "<UUID v7>  -- REQUIRED",
      "approver_id": "<OIDC subject URI | email URI (mailto:) | W3C DID>  -- REQUIRED",
      "approver_identity_type": "oidc | email | did  -- REQUIRED",
      "approver_oidc_issuer": "<OIDC issuer URI>  -- CONDITIONALLY REQUIRED when approver_identity_type is oidc",
      "approver_role": "<role identifier>  -- REQUIRED",
      "approved_at": "<ISO 8601 UTC>  -- REQUIRED",
      "approved_scope": {
        "artifacts": ["system_prompt", "policy_bundle", "tool_manifest", "...  -- REQUIRED"],
        "risk_tier": "low | medium | high | critical  -- REQUIRED",
        "approval_duration_seconds": "<positive integer>  -- REQUIRED",
        "conditions": ["<human-readable condition string>  -- OPTIONAL"]
      },
      "approval_signature": "<Ed25519 | ML-DSA-65 signature by approver key>  -- REQUIRED",
      "approval_method": "hardware-key | software-key | mfa-backed  -- REQUIRED",
      "evidence_uri": "<URI to full approval audit record>  -- REQUIRED"
    }
  ],
  "escalation_policy": {
    "trigger": "<Cedar policy fragment defining escalation conditions>  -- OPTIONAL",
    "escalation_target": "<SPIFFE URI of escalation authority>  -- OPTIONAL",
    "timeout_action": "deny | suspend | alert  -- REQUIRED when escalation_policy is present"
  },
  "hitl_runtime": {
    "interrupt_endpoint": "<HTTPS URI for stopping or suspending the running agent>  -- REQUIRED for Level 2+",
    "override_mechanism": "kill-signal | suspend-and-hold | require-confirmation  -- REQUIRED for Level 2+",
    "monitoring_endpoint": "<HTTPS URI for real-time operation status>  -- REQUIRED for Level 2+",
    "automation_bias_disclosure": "<URI to Art. 14(4)(c) automation bias disclosure document>  -- OPTIONAL"
  }
}
```

**`approver_id`** MUST be a human-attributable identity. SPIFFE SVIDs MUST NOT be used as `approver_id` values - SPIFFE SVIDs identify machine workloads, not natural persons. The preferred form is an OIDC `sub` claim paired with an `approver_oidc_issuer` URI (e.g., `sub: "1234567890"` + `iss: "https://accounts.google.com"`), an email address as a URI (`mailto:approver@example.com`), or a W3C DID bound to a hardware authenticator. For EU AI Act Art. 14 compliance, the approver identity MUST be traceable to a natural person in the deployer's HR or IAM system.

**`approval_method` trust ordering** for regulatory compliance: <!-- CHANGED: SCHEMA F-11 -->
- `hardware-key` (FIDO2 passkey, HSM, or smartcard): satisfies EU AI Act Art. 14 non-repudiation requirements. REQUIRED for `risk_tier: high` or `critical` at Level 2 conformance.
- `mfa-backed` (software key protected by MFA): acceptable for medium-risk approvals only.
- `software-key`: acceptable only for Level 0 non-regulated deployments.

**`hitl_runtime`** block declares the runtime human oversight capabilities required by EU AI Act Art. 14(4) operational oversight obligations. The `hitl_record.approvals` structure satisfies Art. 14 pre-deployment documentation obligations (Art. 14(4)(b)-(e)). The `hitl_runtime` block separately addresses the runtime stop/override capability requirement (Art. 14(4)(a)). Both are required for full Art. 14 compliance. See section 9.1 for the regulatory mapping. <!-- CHANGED: REG-001 -->

Each `approval_signature` is produced by the approver's hardware-backed key (FIDO2/passkey at minimum, HSM for high-risk approvals).

### 3.6 Manifest Signature

<!-- CHANGED: SPEC-10 - moved transparency_log_entry to top-level field outside signed scope to resolve ordering impossibility; SCHEMA F-12 - expanded signed_fields to include all identity fields; CRYPTO-006 - added hybrid signature envelope; CRYPTO-007 - added Ed25519 validation rules; F-08 - replaced transparency_log block with Sigstore-aligned structure -->

```json
"signature": {
  "algorithm": "Ed25519 | ML-DSA-65 | hybrid-Ed25519-ML-DSA-65  -- REQUIRED",
  "key_id": "<key identifier>  -- REQUIRED",
  "key_type": "software | hsm | tee-sealed  -- REQUIRED",
  "signed_at": "<ISO 8601 UTC>  -- REQUIRED",
  "signed_fields": ["@context", "@type", "manifest_id", "previous_manifest_id", "agent_id", "version", "min_verifier_version", "issued_at", "expires_at", "issuer", "crypto_profile", "artifacts", "delegation_chain", "hitl_record", "prior_transparency_log_entry", "log_retention", "data_scope", "operational_lifecycle"],
  "signature_value": "<base64url-encoded signature over RFC 8785 canonical JSON>  -- CONDITIONALLY REQUIRED: REQUIRED when algorithm is Ed25519 or ML-DSA-65",
  "classical_signature": "<base64url-encoded Ed25519 signature>  -- CONDITIONALLY REQUIRED: REQUIRED when algorithm is hybrid-Ed25519-ML-DSA-65",
  "pq_signature": "<base64url-encoded ML-DSA-65 signature>  -- CONDITIONALLY REQUIRED: REQUIRED when algorithm is hybrid-Ed25519-ML-DSA-65"
}
```

**`signed_fields`** is a fixed normative list and MUST NOT be varied by implementations. <!-- CHANGED: closes #156: replaced contradictory prose with an exhaustive signing coverage table; added hitl_record.approvals normalization rule --> The following table enumerates every top-level manifest field and states whether it is part of the signing pre-image. A field marked "Signed" that is absent from the manifest (an omitted OPTIONAL or CONDITIONALLY REQUIRED field) is simply omitted from the pre-image per the null-omission rule in section 2.3; it MUST NOT be serialized as `null`.

**Signing coverage table (normative)**

| Top-level field | In signing pre-image | Notes |
|---|---|---|
| `@context` | Signed | Treated as an ordinary JSON string field (section 2.3). Binding it prevents post-signing context substitution. |
| `@type` | Signed | Treated as an ordinary JSON string field (section 2.3). |
| `manifest_id` | Signed | |
| `previous_manifest_id` | Signed | Binds re-issuance audit chain continuity. |
| `agent_id` | Signed | |
| `version` | Signed | |
| `min_verifier_version` | Signed | Prevents post-signing downgrade of the required verifier version. |
| `issued_at` | Signed | |
| `expires_at` | Signed | |
| `issuer` | Signed | |
| `crypto_profile` | Signed | |
| `artifacts` | Signed | |
| `attestation` | NOT signed | Appended post-signing by hardware (section 3.3). |
| `delegation_chain` | Signed | |
| `hitl_record` | Signed, with `approvals` normalized to `[]` | See the normalization rule below. The HITL requirement itself is tamper-evident; approvals attach post-issuance. |
| `prior_transparency_log_entry` | Signed | Known at issuance time: it references the previous manifest's log entry (section 2.2). Binds the key rotation chain. |
| `log_retention` | Signed | Prevents post-signing weakening of the declared retention policy (section 8.1). |
| `data_scope` | Signed | Prevents post-signing alteration of declared GDPR processing scope (section 9.3). |
| `operational_lifecycle` | Signed | Prevents post-signing alteration of Art. 13 lifecycle disclosures (section 9.4). |
| `signature` | NOT signed | The signing object itself. |
| `transparency_log_entry` | NOT signed | Populated after log submission (see ordering rules below). |

Every top-level field defined by this specification appears in exactly one row of this table. A future spec version that introduces a new top-level field MUST add it to this table.

**`hitl_record.approvals` normalization rule (normative)**: When computing the manifest signing pre-image, the value of `hitl_record.approvals` MUST be normalized to an empty array (`[]`). All other `hitl_record` fields, including `required`, `escalation_policy`, `hitl_runtime`, and any risk-tier metadata, are covered by the issuer signature as-is. This makes the HITL *requirement* tamper-evident (an attacker cannot strip or weaken it without invalidating the issuer signature) while allowing approvals to be attached after the manifest is issued, without re-signing. Approval entries are individually authenticated by their own `approval_signature` and verified separately per section 3.5; they are NOT covered by the issuer signature. Verifiers MUST apply the identical normalization before checking the issuer signature. See ADR-0006 (as amended 2026-06-11).

**Canonical serialization**: The signature covers the RFC 8785 canonical JSON serialization of the named `signed_fields`, after applying the `hitl_record.approvals` normalization rule above. See section 2.3 for the complete canonicalization specification.

**Ed25519 validation rules** <!-- CHANGED: CRYPTO-007 -->: Ed25519 implementations MUST use the cofactorless verification equation (`[S]B == R + [k]A`). Implementations MUST reject non-canonically encoded points (i.e., reject if the encoding does not round-trip through point decoding). Implementations MUST NOT use batch verification unless the batch verifier enforces the same cofactorless equation with canonical encoding checks. Implementations SHOULD use hedged signing (per draft-irtf-cfrg-det-sigs-with-noise) when signing keys reside in hardware signers subject to fault injection.

**Hybrid signature envelope** <!-- CHANGED: CRYPTO-006 -->: When `algorithm` is `hybrid-Ed25519-ML-DSA-65`, both `classical_signature` and `pq_signature` MUST be present. Both signatures cover the identical RFC 8785 canonical JSON byte sequence of `signed_fields`. A verifier MUST verify both signatures and MUST reject the manifest if either fails. Reference: draft-ietf-pquip-hybrid-signature-spectrums for the binding model.

**Transparency log submission ordering** <!-- CHANGED: SPEC-10 -->: The `transparency_log_entry` is a top-level manifest field (see section 3.1) that is NOT part of `signed_fields` and is NOT covered by the `signature`. The correct signing and submission flow is:

1. Canonicalize and sign the `signed_fields` to produce the `signature` object.
2. Submit the signed manifest (without `transparency_log_entry`) to the transparency log.
3. Receive the inclusion proof from the log.
4. Populate the top-level `transparency_log_entry` field.
5. The manifest is complete and ready for use only after step 4.

In hosted mode, the attestation service is responsible for log submission. In self-hosted mode, the signing CLI is responsible.

**Transparency log entry format** <!-- CHANGED: F-08 - aligned to Sigstore bundle spec -->:

```json
"transparency_log_entry": {
  "log_id": "<SHA-256 fingerprint of the log's public key>  -- REQUIRED",
  "log_index": "<integer position in the log>  -- REQUIRED",
  "entry_uuid": "<Rekor entry UUID>  -- REQUIRED",
  "integrated_time": "<Unix epoch integer>  -- REQUIRED",
  "inclusion_proof": {
    "checkpoint": "<signed tree head>  -- REQUIRED",
    "hashes": ["<sha256 hex tile hashes>  -- REQUIRED"],
    "tree_size": "<integer>  -- REQUIRED"
  }
}
```

The `log_id` MUST be the SHA-256 fingerprint of the log's public key, consistent with the Rekor v2 API and the Sigstore root of trust document. The `integrated_time` Unix epoch timestamp is required to enable verifiers to check that the signing event occurred before certificate expiry and to detect backdated signatures.

All production Agent Manifest implementations MUST publish to a public or consortium transparency log. The signature is NOT sufficient without the `transparency_log_entry` for regulatory purposes.

### 3.7 Revocation <!-- CHANGED: SPEC-11 - new section; revocation was referenced throughout but had no data model -->

Revocation is distinct from natural expiry. Natural expiry (the `expires_at` timestamp is exceeded) produces an `EXPIRED` verification result. Explicit revocation produces a `REVOKED` verification result. A verifier MUST check the revocation status endpoint before returning `VALID`.

**Revocation record schema**:

```json
{
  "revocation_id": "<UUID v7>  -- REQUIRED",
  "manifest_id": "<UUID v7 of the revoked manifest>  -- REQUIRED",
  "agent_id": "<SPIFFE URI>  -- REQUIRED",
  "revoked_at": "<ISO 8601 UTC>  -- REQUIRED",
  "reason_code": "KEY_COMPROMISE | ARTIFACT_CHANGE | POLICY_VIOLATION | SCHEDULED_ROTATION | AGENT_DECOMMISSION | OTHER  -- REQUIRED",
  "reason_text": "<human-readable description>  -- OPTIONAL",
  "scope": "manifest | agent  -- REQUIRED",
  "revocation_signature": "<Ed25519 | ML-DSA-65 signature by manifest issuer key or successor key>  -- REQUIRED",
  "transparency_log_entry": "<transparency log entry object per section 3.6>  -- REQUIRED"
}
```

**`scope`** values:
- `manifest`: Revokes only the specific `manifest_id`. Prior manifests for the same `agent_id` are unaffected.
- `agent`: Revokes all current and future manifests for the `agent_id`. Used after key compromise where all historical manifests for the agent are considered untrusted.

**Revocation endpoints**:

```
POST /revoke
Content-Type: application/json
Body: <revocation record>

GET /revocation-status?manifest_id=<UUID v7>
Returns: <revocation record> if revoked, 404 if not revoked
```

Revocation records MUST be published to the same transparency log as the manifest, using a leaf type of `revocation`. The `transparency_log_entry` in the revocation record confirms non-repudiation of the revocation event.


### 3.8 Key Rotation and Manifest Re-signing <!-- CHANGED: closes #42 -->

When the signing key is rotated, the manifest MUST be re-signed and re-published to the transparency log. The old manifest becomes invalid once the new manifest is published and the old key is revoked.

Key rotation procedure:
1. Generate new key pair
2. Create a new manifest with the same artifact bindings, a new `issued_at`, and updated `signature.key_id`
3. Sign the new manifest with the new private key
4. Publish to transparency log
5. Update the verification endpoint to serve the new manifest
6. Revoke the old manifest via the revocation endpoint
7. Revoke the old signing key in the key management system

Implementations MUST NOT re-use the old `manifest_id` for the rotated manifest - a new UUID v7 MUST be generated. The old manifest_id MAY be referenced in the new manifest's metadata for continuity tracing.

## 4. Cryptographic Protocols

### 4.1 Standard Profile

<!-- CHANGED: CRYPTO-005/SCHEMA F-20 - added domain separation for Merkle trees per RFC 9162; CRYPTO-003 - downgraded aTLS to RECOMMENDED with draft version pin; CRYPTO-007 - Ed25519 validation rules moved to 3.6; SCHEMA F-20 - SPIFFE SVID P-256 preference; CRYPTO-001 - RFC 8785 reference -->

The standard cryptographic profile uses the following primitives:

| Operation | Algorithm | Key Size | Notes |
|---|---|---|---|
| Manifest signature | Ed25519 | 256-bit | EdDSA over Curve25519. Cofactorless verification required - see section 3.6. |
| Artifact hashing | SHA-256 | 256-bit output | MUST use NFC-normalized UTF-8 for text artifacts. Hash values prefixed with `sha256:`. |
| Merkle tree (corpus, catalog) | SHA-256 with RFC 9162 domain separation | 256-bit | Leaf: `SHA-256(0x00 \|\| leaf_data)`. Node: `SHA-256(0x01 \|\| left \|\| right)`. See section 4.1.1. |
| Canonical JSON serialization | RFC 8785 (JCS) | N/A | Applies to all signing, hashing, and Merkle construction. See section 2.3. |
| Agent identity | SPIFFE SVID (X.509) | P-256 EC (preferred); RSA-2048 (legacy compatibility only) | New implementations SHOULD use P-256. RSA-2048 permitted only when interfacing with existing PKI that does not support EC. |
| Attestation binding | Platform-native (AMD, Intel, NVIDIA, ARM, AWS) | Platform-defined | See section 3.3.1 for per-platform measurement formats. |
| Transport encryption | TLS 1.3 with attestation extensions per draft-fossati-tls-attestation-08 (or superseding version) | P-256 or X25519 | Mutual attestation over TLS per cMCP spec. Note: attestation TLS extensions are not yet an RFC; implementations MUST track the latest IETF RATS WG draft. Until the RFC is finalized, transport attestation is RECOMMENDED rather than REQUIRED for Level 0/1 deployments. A fallback of attestation over application-layer HTTPS is acceptable for Level 0/1. |
| Transparency log | Rekor (Sigstore) or compatible | N/A | RFC 9162 Certificate Transparency variant. |

##### 4.1.1 Merkle Tree Domain Separation <!-- CHANGED: CRYPTO-005 - explicit domain separation per RFC 9162 to prevent length-extension attacks -->

All Merkle tree constructions in this specification (corpus `merkle_root`, tool `catalog_hash`) MUST use the RFC 9162 / RFC 6962 domain-separated hashing convention:

- **Leaf hash**: `SHA-256(0x00 || leaf_data)` where `leaf_data` is the per-item input bytes as defined in the relevant section (section 3.2.3 for catalog, section 3.2.5.1 for corpus).
- **Interior node hash**: `SHA-256(0x01 || left_child_hash || right_child_hash)`.

The `0x00` and `0x01` domain separation prefixes prevent second-preimage attacks that are possible with plain Merkle-Damgard SHA-256 trees lacking domain separation (as demonstrated in the Certificate Transparency literature). This construction is referenced in RFC 9162 Section 2.1.

An empty tree (zero items) has a defined root of `SHA-256(empty_string)` encoded as `sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

For the post-quantum profile, replace SHA-256 with SHAKE-256(256-bit output) throughout.

### 4.2 Post-Quantum Profile

<!-- CHANGED: CRYPTO-004 - added note that public Sigstore/Rekor does not yet support ML-DSA-65 for Level 3; CRYPTO-006 hybrid mode clarified in section 3.6 -->

For deployments requiring post-quantum security (classified government, financial services with >10 year sensitivity horizon, sovereign deployments), the post-quantum profile MUST be used. This aligns with AGT's existing ML-DSA-65 implementation.

| Operation | Algorithm | NIST Standard | Notes |
|---|---|---|---|
| Manifest signature | ML-DSA-65 | FIPS 204 | Replaces Ed25519. Larger signatures (~3.3KB) but quantum-resistant. |
| Key exchange | ML-KEM-768 | FIPS 203 | Replaces X25519 in attestation TLS handshake. |
| Artifact hashing | SHAKE-256 (256-bit output) | FIPS 202 | Extendable output function; replaces SHA-256. Hash values prefixed with `shake256:`. |
| Hybrid mode | Ed25519 + ML-DSA-65 | Both | Transition period: both signatures required and verified. See section 3.6 for hybrid envelope. |

The `crypto_profile` field in the manifest header MUST be set to `post-quantum` when using this profile. A verifying party that supports only the standard profile MUST reject a post-quantum manifest rather than silently falling back - this prevents downgrade attacks during the transition period.

**Level 3 transparency log note** <!-- CHANGED: CRYPTO-004 -->: As of the date of this specification (June 2026), the public Sigstore/Rekor instance does not yet support ML-DSA-65 signatures. Level 3 deployments MUST use a private Sigstore instance or an equivalent CT-log that supports ML-DSA-65. The parameter set used in the log's dual-signing MUST be documented and pinned by the implementation. As an alternative for the transition period, a separate PQ-signed transparency log entry in DSSE format alongside a classical Rekor entry is acceptable. Level 3 deployments MUST document their transparency log configuration in the `transparency_log_entry.log_id` field.


### 4.3 Canonical Serialization <!-- CHANGED: closes #25 - mandates RFC 8785 -->

All canonical JSON serialization in this specification uses **RFC 8785 (JSON Canonicalization Scheme, JCS)**. Implementations MUST NOT use JSON-LD RDNA normalization, ad-hoc sorted-key serialization, or any other canonicalization standard.

#### Scope

| Use | Input |
|-----|-------|
| Manifest signature pre-image | Fields in `signed_fields` (excludes `attestation`, `signature`, `transparency_log_entry`), with `hitl_record.approvals` normalized to `[]` per section 3.6 |
| `manifest_hash_in_report` pre-image | Full draft manifest JSON before attestation block appended |
| Memory snapshot hash | Memory baseline JSON object |
| Evidence pack hash | Evidence pack JSON envelope |
| Merkle tree leaf nodes (JSON) | Per-entry JSON in audit chain and corpus |

Text artifacts (`system_prompt`, policy content) are hashed as raw UTF-8 NFC byte sequences, not as JSON.

#### Null-valued optional fields

Optional fields with a `null` value MUST be **excluded** from the canonical form. Implementations MUST NOT serialize `"field": null` into the signature pre-image.

#### JSON-LD fields

`@context` and `@type` are treated as ordinary JSON string fields under RFC 8785. Full JSON-LD normalization is NOT used.

#### Normative requirement

Implementations MUST reject manifests where the manifest signature does not verify under RFC 8785 canonicalization. Fallback to alternative canonicalization on failure is NOT permitted.

**References:** RFC 8785 (https://www.rfc-editor.org/rfc/rfc8785) | Test vector: Appendix D

## 5. Verification Protocol

### 5.1 Verification Endpoint

<!-- CHANGED: SPEC-07 - added endpoint hosting models subsection; SCHEMA F-11 - fixed enforce_hitl and enforce_attestation to JSON boolean -->

An Agent Manifest implementation MUST expose a verification endpoint that accepts a manifest ID or manifest document and returns a structured verification result. The endpoint MUST be reachable from any relying party without prior operator-controlled authentication.

```json
POST /verify
Content-Type: application/json
{
  "manifest_id": "<UUID v7>  -- REQUIRED",
  "verification_context": {
    "purpose": "tool-call | audit | delegation | regulatory  -- REQUIRED",
    "verifier_id": "<SPIFFE URI of verifying party>  -- OPTIONAL",
    "required_fields": ["system_prompt", "policy_bundle", "tool_manifest"],
    "enforce_hitl": "<boolean>  -- OPTIONAL, default false",
    "enforce_attestation": "<boolean>  -- OPTIONAL, default false",
    "min_slsa_level": "1 | 2 | 3 | 4  -- OPTIONAL"
  }
}
```

##### 5.1.1 Endpoint Hosting Models <!-- CHANGED: SPEC-07 - new normative subsection -->

Two conformant hosting models are defined:

**SDK-hosted mode**: The agent SDK exposes the verification endpoint locally within the agent process. The endpoint returns hashes of running artifacts (not the artifacts themselves) computed by a trusted component inside the agent process. Access is restricted by mTLS using the agent's SPIFFE SVID. The "without prior operator-controlled authentication" requirement means that a regulator or third-party auditor must be able to reach the endpoint using their own SPIFFE SVID - the operator MUST NOT be able to gate this access.

**hosted mode**: The agent SDK pushes signed hash attestations of running artifacts to the attestation service at startup and on change. The verification endpoint serves verification results using these pushed hashes. The push protocol uses the agent's SPIFFE SVID for authentication to the attestation service. Third-party verifiers access the verification endpoint without prior operator involvement.

Conformance level requirements:
- Level 0/1: Either hosting model is acceptable.
- Level 2+: hosted mode is REQUIRED, or SDK-hosted mode with TEE-sealed attestation of the running hash state.

### 5.2 Verification Result Schema

<!-- CHANGED: CRYPTO-008 - model_identity returns PROVIDER_ASSERTED when model_hash is null; SCHEMA F-13 - added error schemas and ATTESTATION_UNAVAILABLE result; SCHEMA F-14 - added INCOMPATIBLE_VERSION result; SCHEMA F-11 - fixed attestation_verified to JSON boolean; SPEC-12 - added evidence pack format note -->

```json
{
  "verification_id": "<UUID v7>  -- REQUIRED",
  "manifest_id": "<UUID v7>  -- REQUIRED",
  "verified_at": "<ISO 8601 UTC>  -- REQUIRED",
  "result": "VALID | MISMATCH | EXPIRED | REVOKED | INCOMPLETE | ATTESTATION_UNAVAILABLE | INCOMPATIBLE_VERSION  -- REQUIRED",
  "attestation_verified": "<boolean>  -- REQUIRED",
  "fields_verified": {
    "system_prompt": "MATCH | MISMATCH | NOT_BOUND  -- REQUIRED",
    "policy_bundle": "MATCH | MISMATCH | NOT_BOUND  -- REQUIRED",
    "tool_manifest": "MATCH | MISMATCH | NOT_BOUND  -- REQUIRED",
    "model_identity": "MATCH | PROVIDER_ASSERTED | MISMATCH | NOT_BOUND  -- REQUIRED",
    "rag_corpus": "MATCH | MISMATCH | NOT_BOUND  -- REQUIRED",
    "memory_baseline": "MATCH | MISMATCH | NOT_BOUND | EXPIRED  -- REQUIRED",
    "decision_trace": "MATCH | MISMATCH | NOT_BOUND  -- REQUIRED",
    "supply_chain": "MATCH | MISMATCH | NOT_BOUND  -- REQUIRED",
    "delegation_chain": "VALID | INVALID | NOT_PRESENT | UNVERIFIABLE  -- REQUIRED",
    "hitl_record": "APPROVED | EXPIRED | NOT_REQUIRED | MISSING | APPROVAL_INSUFFICIENT  -- REQUIRED"
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
  "verification_signature": "<Ed25519 | ML-DSA-65 signature by the attestation service>"
}
```

`model_identity` returns `PROVIDER_ASSERTED` when `model_attestation_type` is `provider-asserted` (i.e., `model_hash` is null for API-deployed models), so verifiers have an explicit signal distinguishing hardware-rooted model identity from an operator assertion. See section 3.2.4.

`delegation_chain` returns `UNVERIFIABLE` when any `scope_grant.constraints` element is a non-empty array of Cedar statements and the verifier does not support Cedar evaluation - rather than treating the chain as `VALID`.

`hitl_record` returns `APPROVAL_INSUFFICIENT` when an approval exists but does not meet the `approval_method` requirement for the declared `risk_tier` (e.g., `software-key` approval on a `high` risk tier operation at Level 2).

`ATTESTATION_UNAVAILABLE` is returned when the hardware attestation service cannot be reached and the verification cannot be completed. Verifiers receiving this result MUST NOT treat it as `VALID`.

`INCOMPATIBLE_VERSION` is returned when the verifier does not support the manifest's declared `version`. See section 2.2 for version negotiation rules.

##### 5.2.1 Evidence Pack Format <!-- CHANGED: SPEC-12 - new normative subsection -->

An evidence pack is a JSON document with the following structure:

```json
{
  "manifest": "<the full manifest document>",
  "verification_result": "<the section 5.2 verification result object>",
  "trace_envelopes": ["<array of TRACE envelope objects for the session or invocation>"],
  "attestation_report": "<raw platform attestation report bytes, base64url-encoded>"
}
```

`pack_hash` is the SHA-256 of the RFC 8785 canonical JSON of this document. The pack is signed using the TEE-sealed key, with the signature as a detached JWS appended as a top-level `pack_signature` field.

**Access control for confidential payloads**: Tool call payload fields in TRACE envelopes MUST be replaced with their SHA-256 hashes in packs served to unauthenticated verifiers. Full payloads are available only to verifiers presenting a valid SPIFFE SVID with an authorized role declared in the manifest's `policy_bundle`.

### 5.3 Verification Semantics

A `VALID` result means all of the following are true:

- The manifest signature is valid under RFC 8785 canonicalization and the manifest is present in the transparency log. Before checking the issuer signature, the verifier MUST apply the `hitl_record.approvals` normalization rule from section 3.6 (replace `hitl_record.approvals` with `[]` in the signing pre-image); approvals are verified separately against their own `approval_signature`s
- The TEE attestation report confirms the manifest hash is bound to the hardware measurement
- All fields specified in `required_fields` match their running artifacts
- The manifest has not expired
- The manifest has not been revoked (revocation status endpoint MUST be checked before returning VALID)
- If `enforce_hitl` is `true`, at least one HITL approval is present, valid, not expired, and meets the `approval_method` requirement for the declared `risk_tier`
- If `enforce_attestation` is `true`, `audit_key_sealed` is `true` in the attestation block

A `MISMATCH` result means at least one required field does not match its running artifact. The `mismatch_details` array MUST enumerate every mismatched field. A relying party receiving a `MISMATCH` MUST NOT proceed with the operation that triggered verification.

### 5.4 Error Response Schema <!-- CHANGED: SCHEMA F-13 - new section -->

All non-2xx responses from the verification endpoint MUST use the following error response structure:

```json
{
  "error_code": "INVALID_REQUEST | MANIFEST_NOT_FOUND | ATTESTATION_UNAVAILABLE | RATE_LIMITED | INTERNAL_ERROR  -- REQUIRED",
  "error_message": "<human-readable string>  -- REQUIRED",
  "request_id": "<UUID v7>  -- REQUIRED",
  "retry_after_seconds": "<positive integer | null>  -- REQUIRED for RATE_LIMITED, null otherwise"
}
```

HTTP status code mapping:

| `error_code` | HTTP status |
|---|---|
| `INVALID_REQUEST` | 400 |
| `MANIFEST_NOT_FOUND` | 404 |
| `ATTESTATION_UNAVAILABLE` | 503 |
| `RATE_LIMITED` | 429 |
| `INTERNAL_ERROR` | 500 |

### 5.5 Revocation Protocol <!-- CHANGED: SPEC-11 - new section for revocation endpoint -->

The revocation protocol is defined in section 3.7. The verification service MUST implement the following endpoints:

```
POST /revoke
Authorization: mTLS with SPIFFE SVID of authorized revoking party
Content-Type: application/json
Body: <revocation record per section 3.7>
Returns: 201 Created with the published revocation record

GET /revocation-status?manifest_id=<UUID v7>
Returns: <revocation record> if revoked
Returns: 404 if manifest_id is not found in the revocation log
```

Verifiers MUST check the revocation status endpoint before returning any `VALID` result. A 404 from the revocation status endpoint means the manifest has not been explicitly revoked (natural expiry is determined separately by comparing `expires_at` to the current time).

## 6. Integration Architecture

### 6.1 Integration with AGT

The Agent Manifest is the attestation layer above AGT's policy enforcement layer. AGT evaluates policy decisions; the manifest proves those decisions were made under the approved policy, by the approved agent, using the approved tools. The integration points are:

| AGT Component | Agent Manifest Integration Point |
|---|---|
| Cedar policy engine | `policy_bundle.hash` binds the policy bundle that AGT loads at startup. Policy bundle hash in the manifest MUST match `policy_bundle_hash` in the cMCP attestation report. |
| Tool-definition scanner | `tool_manifest.catalog_hash` is the Merkle root over all per-tool (schema, description) leaf hashes that AGT's scanner approved. Any scanner-detected drift produces a mismatch. |
| Audit chain (Decision BOM) | `decision_trace` binding points to AGT's hash-chained audit. The audit signing key is the same key that is TEE-sealed and whose root hash appears in `audit_chain_root`. |
| Agent identity (SPIFFE/DID) | `agent_id` in the manifest MUST match the SPIFFE SVID presented by the agent at every tool call. Identity continuity is the chain that links the manifest to the running agent. |
| Compliance export | The verification result (section 5.2) is the AGT compliance export for external regulators - it replaces the current SOC 2 / NIST AI RMF export with a hardware-signed equivalent. |

### 6.2 Integration with cMCP

The Agent Manifest and cMCP are complementary primitives that operate at different layers of the same trust stack. cMCP attests the runtime enforcement layer; the Agent Manifest attests the complete agent identity surface. Their attestation fields overlap deliberately:

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

<!-- CHANGED: F-02 - fixed manifest extension to use _meta and experimental capability rather than non-standard clientInfo fields -->

When an agent's MCP client connects to an MCP server, the client SHOULD signal manifest support using two mechanisms:

**Current implementations** (compatible with MCP 2025-11-25): Use the `_meta` field on the `initialize` request params with a namespaced key, and signal support via the `experimental` capability:

```json
{
  "method": "initialize",
  "params": {
    "clientInfo": {
      "name": "<agent name>",
      "version": "<agent version>"
    },
    "capabilities": {
      "experimental": {
        "co.opaque.agentManifest": { "version": "0.1" }
      }
    },
    "_meta": {
      "co.opaque.agentManifest": {
        "id": "<UUID v7>",
        "verificationEndpoint": "<HTTPS URI>"
      }
    }
  }
}
```

**Future MCP versions**: This specification will file an AAIF Spec Enhancement Proposal (SEP) to add `agentManifestId` and `agentManifestVerificationEndpoint` as optional fields on the MCP `Implementation` type. When that SEP is accepted, those fields MAY be placed directly on `clientInfo`. Until then, the `_meta` approach above is the conformant mechanism.

An MCP server implementing the Agent Manifest extension SHOULD verify the manifest before servicing any tool calls. For cMCP Phase 2 servers running inside a TEE, this verification is performed inside the TEE and the result is included in the per-call evidence pack.

#### 6.3.2 Manifest Binding in Tool Call Evidence

<!-- CHANGED: SCHEMA F-11 - fixed hitl_required to JSON boolean; SCHEMA F-21 - added normative resolution rule for hash conflicts between TRACE and manifest -->

Every tool call evidence record (TRACE envelope) produced by cMCP MUST include the agent's manifest ID and the verification result at the time of the call:

```json
{
  "trace_id": "<UUID v7>",
  "agent_id": "<SPIFFE URI>",
  "agent_manifest_id": "<UUID v7>",
  "manifest_verification_result": "VALID | MISMATCH | EXPIRED | REVOKED | INCOMPLETE | ATTESTATION_UNAVAILABLE | INCOMPATIBLE_VERSION",
  "tool_id": "<reverse-domain tool identifier>",
  "policy_hash": "sha256:<64-hex-chars>",
  "catalog_hash": "sha256:<64-hex-chars>",
  "decision": "allow | deny | require-approval",
  "decision_reason": "<Cedar policy fragment that made this decision>",
  "payload_classification": "public | internal | confidential | restricted",
  "egress_destination": "<FQDN | IP | none>",
  "hitl_required": "<boolean>",
  "hitl_approval_id": "<UUID v7> | null",
  "timestamp": "<ISO 8601 UTC>",
  "tee_measurement": "<platform-specific measurement>",
  "signature": "<Ed25519 | ML-DSA-65 by TEE-sealed key>"
}
```

**Hash conflict resolution** <!-- CHANGED: SCHEMA F-21 -->: If `policy_hash` in the TRACE envelope differs from `artifacts.policy_bundle.hash` in the agent manifest, the TRACE MUST set `manifest_verification_result: MISMATCH` for that call. The manifest is the authoritative source for approved artifact hashes; the TRACE reflects runtime measurements. A non-empty `mismatch_details` array in the verification result (section 5.2) MUST be generated for every such discrepancy. The `manifest_verification_result` field MUST use the same enum values as the `result` field in section 5.2 - no additional values. Any TRACE with `manifest_verification_result: MISMATCH` or `EXPIRED` MUST NOT be accepted as evidence of a valid tool call for regulatory reporting purposes.

## 7. Threat Model

### 7.1 Threat Classes Addressed

| Threat | Description | Without Agent Manifest | With Agent Manifest |
|---|---|---|---|
| T1 - Prompt Substitution | System prompt replaced in memory between approval and runtime | Undetectable. No binding exists. | `system_prompt.hash` mismatch immediately detectable at verification. |
| T2 - Policy Swap | Cedar policy bundle replaced with permissive policy | Detectable by AGT hash check (software). Bypassable by root. | `policy_bundle.hash` bound to TEE measurement. Hardware-impossible to swap silently. |
| T3 - Tool Rug Pull | MCP server mutates tool definition after approval | Detectable by AGT scanner (software). Re-hash bypassable. | Per-tool leaf commits to both `schema_hash` and `description_hash`. Any mutation breaks `catalog_hash` Merkle root. |
| T4 - Model Substitution | Different model version runs than was approved | Undetectable. No standard binding. | `model_identity.version` bound. API models: version check at call time. Local models: binary hash. |
| T5 - RAG Corpus Poisoning | Malicious documents injected into knowledge base | Undetectable without corpus audit. | `rag_corpus.merkle_root` changes. Manifest invalidated. Verifier detects before agent runs. |
| T6 - Scope Laundering | Sub-agent claims broader permissions than delegating agent granted | Undetectable. No delegation chain standard. | `delegation_chain.scope_grant` is signed at each hop. Broader scope fails signature verification. |
| T7 - Rogue Administrator | Operator with root access rewrites audit logs or policy | Bypassable. Software signing key is operator-held. | `audit_key_sealed: true`. Key never leaves TEE. Log reconstruction hardware-impossible. |
| T8 - HITL Forgery | Human approval record fabricated without actual human review | Undetectable without physical audit. | `approval_signature` produced by approver hardware key. Forgery requires key compromise. |
| T9 - Supply Chain Compromise | Malicious dependency runs as approved binary | SLSA covers build-time. Runtime drift undetected. | `container_image_digest` in TEE measurement. Modified binary produces measurement mismatch. |
| T10 - Memory Drift | Long-running agent accumulates unreviewed memory changes | Undetectable. No memory baseline standard. | `memory_baseline.snapshot_hash` bound. `ttl_seconds` forces re-approval of memory state. |

### 7.2 Out of Scope

The following threats are explicitly out of scope for this specification:

- **Semantic prompt injection at the model layer** - the manifest proves what prompt was approved; it cannot prevent a model from being misled by adversarial inputs within that prompt's scope.
- **Model weight poisoning** - the `model_identity` binding attests which model is running; it does not attest the model's internal weights for locally-deployed models beyond the binary hash.
- **Side-channel attacks on the TEE** - hardware vulnerabilities in AMD SEV-SNP, Intel TDX, or NVIDIA Blackwell that allow measurement extraction are out of scope. These are platform-level threats addressed by hardware vendors.
- **Denial of service against the verification endpoint** - availability of the verification service is an operational concern, not a correctness concern.
- **Human approver compromise** - if an authorized approver's hardware key is compromised, the HITL record is valid despite the fraudulent approval. Key management and approver identity assurance are out of scope.

## 8. Conformance Requirements

### 8.1 Implementation Levels

<!-- CHANGED: REG-003 - removed OCC AI guidance claim; SCHEMA F-11 - updated level descriptions; REG-002 - added log retention requirement for Level 2; REG-005 - clarified GDPR Art. 32 claim -->

| Level | Name | Requirements | Use Case |
|---|---|---|---|
| Level 0 | Software-only | All artifact bindings. Standard crypto profile. Transparency log publication. No TEE requirement. | Development, staging, non-regulated environments. |
| Level 1 | TEE-attested | Level 0 plus: TEE attestation block. `audit_key_sealed: true`. `container_image_digest` verified by hardware. | Enterprise production. Satisfies EU AI Act Art. 15 (cybersecurity). |
| Level 2 | Full stack | Level 1 plus: All 10 artifacts bound (per section 3.1 mapping table). HITL approvals present. Delegation chain for multi-agent. Phase 2 cMCP for all MCP servers. `log_retention.minimum_retention_days >= 180`. `drift_policy: deny-on-drift` or `alert-on-drift`. | Regulated industries. Satisfies DORA Art. 9, GDPR Art. 32 (when `data_scope` fields are populated for EU personal data processing). |
| Level 3 | Post-quantum | Level 2 plus: ML-DSA-65 signatures. ML-KEM-768 key exchange. SHAKE-256 hashing. Private Sigstore instance supporting ML-DSA-65. | Sovereign deployments, classified, financial services with long-horizon sensitivity. |

**Log retention requirement** <!-- CHANGED: REG-002 -->: Level 2 conformance requires a declared and enforced log retention configuration. The `log_retention` top-level manifest field MUST be present:

```json
"log_retention": {
  "minimum_retention_days": "<integer, REQUIRED, minimum 180 for EU AI Act compliance>",
  "regulatory_retention_override": "<integer days, OPTIONAL, for sector-specific overrides (e.g. DORA: 1825 days / 5 years)>",
  "retention_enforced_by": "<identifier of system responsible for enforcing retention policy, REQUIRED>"
}
```

The EU AI Act (Art. 26 via Art. 12 and recital obligations) requires a minimum of 180 days (six months) log retention. Financial entities subject to DORA Art. 25(1) may require up to 1825 days (five years). `minimum_retention_days` MUST be at least 180 for EU AI Act compliance.

### 8.2 Conformance Test Suite

A conformant Agent Manifest implementation MUST pass all tests in the reference test suite. The suite is organized into four modules:

| Module | Tests | Coverage |
|---|---|---|
| AM-BIND | 47 tests | Artifact binding correctness: hash computation, normalization, Merkle tree construction, schema validation. |
| AM-CRYPTO | 38 tests | Signature generation and verification: Ed25519 (cofactorless), ML-DSA-65, hybrid, transparency log inclusion, RFC 8785 canonicalization. |
| AM-ATTEST | 29 tests | TEE attestation binding: manifest hash in report, field cross-checks with cMCP, `audit_key_sealed` enforcement, per-platform measurement format validation. |
| AM-VERIFY | 52 tests | Verification endpoint: result schema, mismatch detection, delegation chain validation, HITL verification, revocation status check, error response schemas. |
| AM-COMPAT | 31 tests | AGT integration, cMCP integration, MCP protocol extension, SLSA provenance binding. |

Total: 197 conformance tests. The test suite will be published as an open-source repository alongside the AGT donation to AAIF. Conformance claims MUST reference a specific test suite version and MUST include a passing test run against the reference implementation.

## 9. Regulatory Mapping

### 9.1 EU AI Act

<!-- CHANGED: REG-001 - corrected Art. 14 mapping to distinguish pre-deployment and runtime obligations; CRYPTO-008/REG-006 - added model attestation type note; REG-009 - added Art. 13(3)(c)(e) operational lifecycle fields; REG-005 - added Art. 22 note; REG-006 - added Annex III classification guidance subsection -->

| Article | Requirement | Agent Manifest Satisfaction |
|---|---|---|
| Art. 13 - Transparency | High-risk AI systems must be transparent about their operation | `agent_id`, `model_identity`, and `tool_manifest` provide the disclosure primitive. Note: when `model_attestation_type` is `provider-asserted`, the model identity binding is an operator assertion, not hardware-rooted attestation - this distinction is surfaced in verification results and may not satisfy the highest-risk tier transparency requirements for Art. 13. |
| Art. 14 - Human Oversight (pre-deployment) | High-risk AI must allow humans to understand and intervene; oversight measures documented | `hitl_record.approvals` satisfies Art. 14(4)(b)-(e) pre-deployment documentation obligations. `approval_signature` by hardware key satisfies non-repudiation for the approval event. |
| Art. 14 - Human Oversight (operational) | Art. 14(4)(a) requires the ability to stop or interrupt the system safely during operation | `hitl_record.hitl_runtime.interrupt_endpoint` and `override_mechanism` satisfy the runtime stop/interrupt capability requirement. Both the pre-deployment approvals and the runtime oversight fields are required for full Art. 14 compliance. |
| Art. 15 - Accuracy and Cybersecurity | High-risk AI must be resilient to errors; cybersecurity measures documented | TEE attestation + `container_image_digest` satisfies the cybersecurity measure documentation requirement. Mismatch detection satisfies resilience. |
| Art. 26 - Obligations for Deployers | Deployers must monitor operation and report serious incidents; logging required | `decision_trace` + `audit_chain_root` provides the monitoring log. TEE-sealed signing key satisfies tamper-evidence requirement. |
| Art. 12 - Record-keeping (tamper-evidence) | High-risk AI must keep logs automatically; logs must be accurate | `audit_key_sealed: true` satisfies the accuracy requirement - logs cannot be retroactively altered without detection. |
| Art. 12 - Record-keeping (retention) | Art. 26(6) requires minimum six-month log retention | Satisfied only when `log_retention.minimum_retention_days >= 180` is declared and enforced. Required for Level 2 conformance. |
| Art. 22 - Automated decision-making | Where agents make automated decisions with significant effects on individuals, disclosure is required | When `data_scope.automated_decision_making` is `true`, Art. 22 disclosure obligations are triggered. The manifest's `data_scope` field (section 9.3) provides the machine-readable signal. |

#### 9.1.1 EU AI Act Annex III Classification Guidance <!-- CHANGED: REG-006 - new subsection -->

The obligations mapped in section 9.1 (Arts. 12-15, 26) apply only to high-risk AI systems under EU AI Act Annex III. Operators MUST determine whether their agent deployment qualifies before asserting compliance. The following Annex III categories are most likely to cover AI agent deployments:

| Annex III Point | Category | Example Agent Use Cases |
|---|---|---|
| Point 1 | Biometric identification and categorisation | Agents that identify or categorise individuals by biometric data |
| Point 2 | Critical infrastructure management | Agents managing energy, water, transport, or financial infrastructure |
| Point 4 | Employment and worker management | Agents performing recruitment screening, work allocation, or employee performance monitoring |
| Point 5 | Access to essential private/public services | Agents performing creditworthiness assessment, risk scoring for insurance, benefits eligibility determination |
| Point 6 | Law enforcement | Agents used in risk assessment, evidence analysis, or profiling in law enforcement contexts |

**Decision guidance**: If the agent deployment falls within one of the above categories, Arts. 12-15 and 26 obligations apply and Level 2 conformance or above is recommended. If the deployment does not fall within Annex III, the manifest remains a useful provenance and governance primitive but the regulatory obligations in this section are not legally mandated.

**GPAI model providers** (Anthropic, OpenAI, Google, etc.) are subject to separate obligations under Arts. 51-53 of the EU AI Act. These are distinct from the high-risk system obligations described here, which apply to operators deploying agents built on top of GPAI models.

Operators in financial services should note that agents performing creditworthiness assessment or risk scoring for life and health insurance (Annex III Point 5(b)) are likely high-risk regardless of the underlying model provider.

### 9.2 DORA (EU) and Financial Sector Guidance

<!-- CHANGED: REG-003 - removed OCC AI guidance claim and replaced with accurate language; REG-004 - corrected NIST GOVERN 1.7 mapping; REG-007 - added concentration risk and registry obligation notes -->

| Framework | Requirement | Agent Manifest Satisfaction |
|---|---|---|
| DORA Art. 9 | ICT systems must be resilient; evidence of what ran and when | Verification result + `evidence_pack` provides per-invocation evidence of what agent ran, under what policy, at what time. Hardware-signed. |
| DORA Art. 28 (third-party oversight) | Third-party ICT risk management; independent oversight | an independent attestation authority. Verification endpoint reachable by regulator without operator involvement. |
| DORA Art. 28(3) (ICT registry) | Financial entities must maintain a registry of all ICT third-party service arrangements | Agent Manifest records, when aggregated, constitute the primary data source for the Art. 28(3) ICT third-party registry. Manifests SHOULD be exported to the financial entity's registry system. The `attestation_service` field enables documentation of the attestation service dependency. |
| DORA Art. 28(4) (concentration risk) | Financial entities must assess concentration risk for critical ICT dependencies | The attestation service is a critical ICT dependency for Level 2+ deployments and MUST be documented in the Art. 28(4) concentration risk assessment. Financial entities MUST define an exit strategy per Art. 28(8) covering the scenario where the attestation service is unavailable. |
| NIST AI RMF - GOVERN 1.2 | Organizational teams are committed to transparent and accountable AI risk management policies | `policy_bundle.hash` bound to hardware attestation proves policy implementation, not just documentation. |
| NIST AI RMF - GOVERN 1.7 | Processes and procedures for decommissioning and phasing out AI systems safely | Revocation records (section 3.7) published to the transparency log serve as the decommissioning artifact. The `decision_trace` records for decommissioned agents are retained per `log_retention` policy. `agent_id` continuity in the rotation chain enables post-decommission audit. |

**OCC AI guidance note** <!-- CHANGED: REG-003 -->: OCC/FDIC/Fed Bulletin 2026-13 (issued 17 April 2026) explicitly excludes generative AI and agentic AI from scope. Financial entities deploying agents MUST apply existing enterprise risk management frameworks (SR 11-7 successor guidance, FDIC FIL-22-2023 model risk principles) until dedicated agentic AI guidance is issued. The Agent Manifest supports general model governance obligations - version tracking, capability declarations, audit trails - that financial entities should document under their existing frameworks pending OCC rulemaking. Section 10.2 (v0.2 roadmap) includes tracking the OCC RFI process.

### 9.3 GDPR, HIPAA, and Additional Regulatory Frameworks <!-- CHANGED: REG-005/REG-008 - new section -->

#### GDPR Art. 32 and Art. 35

GDPR Art. 32 compliance for AI agents requires: attribute-based access control documented at the agent level, tamper-evident audit records for every AI agent interaction with personal data, and prompt injection defenses as Art. 32 security controls. The manifest's artifact hashing, TEE-sealed audit keys, and tool manifest scoping support Art. 32's technical measures requirement.

The following `data_scope` field MUST be populated when the agent processes EU personal data (required for Level 2 conformance when processing EU personal data):

```json
"data_scope": {
  "personal_data_categories": ["<GDPR Art. 30 processing categories>  -- REQUIRED when processing personal data"],
  "legal_basis": ["<GDPR Art. 6 legal basis identifiers>  -- REQUIRED when processing personal data"],
  "automated_decision_making": "<boolean>  -- REQUIRED, triggers Art. 22 disclosure when true",
  "dpia_reference": "<URI to Art. 35 DPIA document>  -- CONDITIONALLY REQUIRED for high-risk processing"
}
```

When `automated_decision_making` is `true`, Art. 22 disclosure obligations are triggered and the deployer MUST provide information to affected individuals about the automated decision-making mechanism.

For Art. 35 DPIA support, the `dpia_reference` URI points to the DPIA document covering this agent deployment. The manifest's `data_scope.personal_data_categories` and `tool_manifest` fields provide the information inventory that feeds the DPIA.

#### HIPAA Security Rule

Healthcare AI agents processing protected health information (PHI) are subject to the HIPAA Security Rule (45 CFR 164.312). The following manifest fields directly address HIPAA technical safeguard requirements:

| HIPAA Requirement | CFR Reference | Agent Manifest Satisfaction |
|---|---|---|
| Audit controls | 45 CFR 164.312(b) | `decision_trace.audit_chain_root` + `audit_key_sealed: true` provides hardware-anchored, tamper-evident audit controls. |
| Integrity controls | 45 CFR 164.312(c)(1) | Artifact hash bindings ensure PHI-processing configurations are not altered without detection. |
| Transmission security | 45 CFR 164.312(e)(1) | TLS 1.3 transport with attestation extensions (section 4.1) satisfies the transmission security standard. |

#### PCI-DSS v4.0

Financial agents processing cardholder data are subject to PCI-DSS v4.0. Relevant requirements:

| PCI-DSS Requirement | Coverage |
|---|---|
| Requirement 10.3 (audit log protection) | `audit_key_sealed: true` provides hardware-rooted protection against audit log destruction and unauthorized modification, directly addressing PCI-DSS Req. 10.3. |
| Requirement 12.3.2 (targeted risk analysis) | The manifest's artifact binding and verification protocol provides the evidence base for targeted risk analysis of AI-driven controls. |

#### FedRAMP High

Federal agencies evaluating the Agent Manifest for use in FedRAMP High environments should note the following control family alignments:

| FedRAMP Control | Coverage |
|---|---|
| AC-2 (Account Management) | `agent_id` SPIFFE SVID provides machine identity; `delegation_chain` provides access authorization chain. |
| AU-2, AU-9 (Audit and Accountability) | `decision_trace` + `audit_key_sealed` satisfies audit generation (AU-2) and audit protection (AU-9). |
| SA-12 (Supply Chain Risk Management) | `supply_chain` block with SLSA provenance and SBOM binding directly addresses SA-12. |
| SC-28 (Protection of Information at Rest) | TEE-sealed audit key ensures audit records at rest are protected from operator-level access. |

### 9.4 Operational Lifecycle Disclosures <!-- CHANGED: REG-009 - new section for Art. 13(3)(c)(e) -->

EU AI Act Art. 13(3)(c) and (e) require that instructions for use include information about predetermined changes to the system and its performance, and the expected operational lifetime and maintenance measures. The following `operational_lifecycle` field satisfies these requirements:

```json
"operational_lifecycle": {
  "expected_lifetime_days": "<integer>  -- REQUIRED for Art. 13 compliance",
  "planned_maintenance_schedule": "<cron expression or human-readable description>  -- OPTIONAL",
  "update_policy": "<URI to provider's software update policy>  -- OPTIONAL",
  "reissuance_triggers": ["model_version_change | policy_major_version | tool_schema_change | <other>"]
}
```

The Art. 13 row in section 9.1 cross-references `operational_lifecycle.expected_lifetime_days` for Art. 13(3)(e) and `operational_lifecycle.reissuance_triggers` for Art. 13(3)(c).

## 10. Roadmap and Standards Path

### 10.1 Version 0.1 - This Specification

- Complete data model for all 10 artifacts
- Cryptographic protocol definitions for standard and post-quantum profiles
- Verification API specification with error schemas and revocation protocol
- TEE attestation binding protocol with per-platform profiles
- Conformance test suite (197 tests)
- Reference implementation targeting AAIF + cMCP

### 10.2 Version 0.2 - Design Partner Feedback

<!-- CHANGED: REG-003 - added OCC RFI tracking to roadmap -->

Targets: Q3 2026. Input from ServiceNow, JPMC, Across AI, and sovereign AI partners.

- Memory baseline protocol for stateful agents (v0.1 defines the binding; v0.2 defines the checkpoint protocol)
- RAG corpus incremental update protocol - how to bind a delta without re-hashing the full corpus
- Multi-model manifest - binding for agents that use different models for different subtasks
- Federated verification - cross-organizational manifest verification without shared infrastructure
- A2A delegation chain revocation - how to invalidate a mid-chain delegation without revoking the full manifest
- OCC RFI tracking - align to any agentic AI governance guidance issued by OCC, FDIC, or the Federal Reserve following the 2026 RFI process
- AAIF scanner registry - define a registered scanner identifier format for `poisoning_scan.scanner_version`

### 10.3 Version 1.0 - Proposed AAIF Standard

<!-- CHANGED: F-06 - added @context URL transfer as AAIF donation condition -->

Target: Q1 2027. Submission to AAIF alongside the AGT donation.

- Finalized data model with no breaking changes from v0.2
- Interoperability validated with at least three independent implementations
- AAIF working group review and endorsement
- Reference implementation published as AAIF project
- Conformance certification program defined
- Transfer of `agentmanifest.agentrust.io` (or successor provisional domain) to AAIF-controlled infrastructure as a condition of v1.0 acceptance. The canonical `@context` URL will be updated to an AAIF-controlled namespace at this point.

### 10.4 Relationship to Existing Standards

<!-- CHANGED: F-04 - corrected A2A row to accurately describe the relationship -->

| Standard | Relationship |
|---|---|
| SPIFFE/SPIRE | Agent Manifest uses SPIFFE SVIDs for `agent_id` and `principal_id`. Agent Manifest extends, not replaces, SPIFFE. |
| SLSA | `supply_chain.slsa_provenance` references SLSA attestations. Agent Manifest adds runtime measurement on top of SLSA build-time provenance. |
| CycloneDX / SPDX (SBOM) | `supply_chain.sbom` references a CycloneDX or SPDX SBOM. Agent Manifest binds the SBOM hash; it does not replace SBOM tooling. |
| MCP (Anthropic / AAIF) | Agent Manifest extends MCP's `initialize` handshake and tool call protocol. It is protocol-agnostic but MCP is the reference implementation. |
| A2A (Google / Linux Foundation) | No current A2A standard defines a delegation chain. The Agent Manifest delegation chain is a proposed primitive designed for protocol agnosticism, intended to align with A2A specifications as they mature. |
| Sigstore / Rekor | `transparency_log_entry` uses Rekor or a compatible CT log. Sigstore tooling (cosign) can sign manifests in the standard profile. Level 3 deployments require a private Sigstore instance with ML-DSA-65 support (see section 4.2). |
| OpenTelemetry | `decision_trace` integrates with OTel spans. Each manifest-bound tool call produces an OTel span with the manifest ID as a baggage item. |
| CoSAI WS1 | `supply_chain` provenance aligns with CoSAI Working Stream 1 (AI supply chain security). Agent Manifest is a candidate for CoSAI WS1 recommendation. |
| RFC 8785 (JCS) | All canonical JSON serialization uses RFC 8785. This is a normative dependency. |
| RFC 9162 (Certificate Transparency v2) | Merkle tree construction and transparency log structures follow RFC 9162. |
| RFC 9334 (RATS Architecture) | The attestation service plays the RATS Verifier role. Platform-native attestation reports are normalized to EAT (RFC 9528) for third-party verification. |
| RFC 9562 (UUID v7) | All UUID fields in the manifest use UUID v7 per RFC 9562. |

## 11. Appendix

### A. Glossary

| Term | Definition |
|---|---|
| Agent Manifest | The cryptographically signed, hardware-attestable document defined by this specification. |
| Attestation | A hardware-produced measurement that proves what code is running inside a TEE without trusting the operator. |
| A2A | Agent-to-Agent protocol. A wire protocol for inter-agent communication, currently governed by the Linux Foundation. As of the date of this specification, no A2A standard defines a delegation chain or inter-agent trust primitive. |
| AGT | Agent Governance Toolkit. The open-source agent governance framework created by Imran Siddique; reference implementation of this specification's software layer. |
| Catalog Hash | Merkle root over per-tool leaf hashes, where each leaf commits to both the tool's schema hash and description hash. |
| cMCP | Confidential MCP. A hardware-attested MCP runtime; the reference implementation of this specification's attestation layer. |
| Decision BOM | Decision Bill of Materials. AGT's per-audit-record structure capturing the inputs, policy decision, and outcome for each governance decision. |
| Delegation Chain | The ordered sequence of principals and scope grants from root human principal to the current agent. An original design of this specification; no published A2A standard defines an equivalent primitive. |
| HITL | Human-in-the-Loop. A human oversight event that is recorded and bound in the manifest. |
| JCS | JSON Canonicalization Scheme. RFC 8785. The canonical JSON serialization algorithm used throughout this specification. |
| Manifest ID | A UUID v7 (time-ordered, per RFC 9562) that uniquely identifies a specific version of an Agent Manifest. Immutable per issuance. |
| Merkle Root | The root hash of a Merkle tree over a set of artifact hashes using RFC 9162 domain-separated construction. Changing any artifact changes the root. |
| ML-DSA-65 | Module Lattice-based Digital Signature Algorithm, parameter set 65. NIST FIPS 204. Post-quantum signature scheme. |
| PROVIDER_ASSERTED | A verification result status for `model_identity` indicating the model binding is an operator assertion rather than a hardware-rooted hash binding. Returned when `model_attestation_type` is `provider-asserted`. |
| RATS | Remote ATtestation procedureS. IETF architecture (RFC 9334) for remote attestation. The attestation service acts as a RATS Verifier. |
| Rug Pull | An attack where a previously-approved tool endpoint silently mutates its capability definitions after the security review concluded. |
| Scope Laundering | An attack where a sub-agent claims broader permissions than its delegating principal granted. |
| TEE | Trusted Execution Environment. Hardware-isolated memory region (AMD SEV-SNP, Intel TDX, NVIDIA Blackwell, ARM CCA) where code runs protected from the host OS and operator. |
| TRACE Envelope | The portable, hardware-signed evidence artifact produced by cMCP for every tool call. Contains the verification result plus per-call decision evidence. |

### B. Change Log

| Version | Date | Author | Changes |
|---|---|---|---|
| 0.1 | June 2026 | Imran Siddique | Initial draft. Complete data model, 10 artifacts, cryptographic protocols, verification API, conformance requirements, regulatory mapping. |

### C. Acknowledgments

This specification builds on architectural work developed across the Agent Governance Toolkit (AGT), the Confidential MCP (cMCP) specification, the Opaque Systems Agent Trust Platform design, and prior research into Cryptographic Agent Provenance and Verifiable Agent Delegation. The delegation chain design is informed by the IATP (Inter-Agent Trust Protocol) architecture developed in the context of the Agent Internet proposal. The post-quantum profile extends AGT's existing ML-DSA-65 implementation. The HITL record design is informed by the EU AI Act Art. 14 implementation guidance from the European AI Office.

---

*Agent Manifest Specification v0.1 - Opaque Systems - June 2026*


### D. RFC 8785 Canonical JSON Test Vector <!-- CHANGED: closes #25 -->

**Input:**
```json
{"version":"0.1","issued_at":"2026-06-23T09:00:00Z","agent_id":"spiffe://trust.example/agent/kyc/prod-001"}
```

**RFC 8785 canonical form (UTF-8, no trailing newline):**
```
{"agent_id":"spiffe://trust.example/agent/kyc/prod-001","issued_at":"2026-06-23T09:00:00Z","version":"0.1"}
```
Keys sorted lexicographically. No whitespace.

**SHA-256 of canonical form:**
```
b83293348255f4427dc030478f354b83f4f82662223be0926ad9f2db946b5319
```

**Verification:**
```python
from jcs import canonicalize  # pip install jcs
import hashlib
obj = {"version":"0.1","issued_at":"2026-06-23T09:00:00Z",
       "agent_id":"spiffe://trust.example/agent/kyc/prod-001"}
canonical = canonicalize(obj)
assert hashlib.sha256(canonical).hexdigest() == "b83293348255f4427dc030478f354b83f4f82662223be0926ad9f2db946b5319"
```