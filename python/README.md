# agent-manifest

**Cryptographically anchor all 10 artifacts defining an AI agent at deployment.**

The Agent Manifest SDK implements the Agent Manifest Specification v0.1  -  a hardware-attestable document that binds every artifact defining an agent's behavior (system prompt, policy bundle, tool schemas, model identity, RAG corpus, memory state, audit chain, delegation chain, supply chain, and human approvals) into a single tamper-evident identity primitive.

```
pip install agent-manifest
```

## Why

A signed JWT proves who called an API. An Agent Manifest proves who the agent **was**, what it was **allowed to do**, how it was **built**, what it **decided**, who **approved** it, and whether any of that changed between approval and execution.

```python
from agent_manifest import (
    Manifest, ArtifactBindings,
    SystemPromptBinding, PolicyBundleBinding, ModelIdentityBinding,
    CryptoProfile, DeploymentType, EnforcementMode, PolicyLanguage,
    generate_ed25519, Ed25519Signer,
)
from agent_manifest._types import HashValue, ManifestId
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc)

manifest = Manifest(
    manifest_id=ManifestId("018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"),
    agent_id="spiffe://trust.example/agent/kyc/prod",
    issued_at=now,
    expires_at=now + timedelta(days=90),
    issuer="spiffe://trust.example/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(
        system_prompt=SystemPromptBinding(
            hash=HashValue("sha256:" + "a" * 64),
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
            provider="example-provider",
            model_id="example-model-1",
            version="20251001",
            deployment_type=DeploymentType.api,
            bound_at=now,
        ),
    ),
)

keypair = generate_ed25519()
signer = Ed25519Signer(keypair)
sig_block = signer.sign(manifest.model_dump(mode="json", by_alias=True))
print(sig_block["algorithm"])   # Ed25519
print(sig_block["key_id"])      # sha256:<hex>
```

### Composition-only manifests

Repository scanners can bind the artifacts they know before a model or runtime
session exists. Set `profile="composition-only"` and explicitly name every
artifact not bound by the document in `unbound_artifacts`. The verifier returns
`INCOMPLETE`, not `VALID`, so this narrower document cannot be mistaken for a
Level 0 agent manifest. Both fields are signature-covered.

```python
manifest = Manifest(
    # identity, validity, issuer, and crypto fields omitted here for brevity
    profile="composition-only",
    unbound_artifacts=[
        "tool_manifest", "model_identity", "rag_corpus", "memory_baseline",
        "decision_trace", "delegation_chain", "supply_chain", "hitl_record",
    ],
    artifacts=ArtifactBindings(
        system_prompt=system_prompt_binding,
        policy_bundle=policy_bundle_binding,
    ),
)
```

### Memory delta verification

The private SDK helper `agent_manifest._memory_delta.verify_delta` checks both
the append-only proof and the operations claimed to have produced the advance:

```python
verdict = verify_delta(
    previous_checkpoint, new_checkpoint,
    appended_ops, consistency_proof,
    representation="kv",  # or "vector" / "graph", matching the checkpoints
)
```

Migration for existing callers: pass only the operations appended since the
previous checkpoint, in order, and supply the required `representation` keyword.
The whole new log or an empty list for a nonempty advance is rejected as `drift`.
Previously the helper ignored `ops`, so its acceptance did not authenticate them.
Existing checkpoint roots and consistency proofs retain their formats.

Only fields included by the existing representation's leaf encoder are bound;
extra operation metadata is not authenticated. The caller remains responsible for
trusted checkpoints and policy inputs. This helper does not verify checkpoint
approval signatures or establish whether the resulting memory behavior is safe.
### Human approval and current applicability

`VerificationResult.hitl_admissibility` reports present applicability separately
from `fields_verified.hitl_record`. The existing `APPROVED` result means the
implemented approval checks passed; it does not establish that the approver still
has authority or that the approval applies to current circumstances. The SDK has
no current-state evidence input or successor-discovery mechanism for this decision.

| Status | Reason | Meaning |
|---|---|---|
| `UNDECIDABLE` | `current_state_evidence_unavailable` | Approval checks passed, but current applicability is unknown. |
| `UNDECIDABLE` | `approval_checks_not_satisfied` | Approval checks did not pass; they cannot establish applicability. |
| `UNDECIDABLE` | `verification_incomplete` | Verification stopped before HITL evaluation, or an older result lacks this metadata. |
| `NOT_REQUIRED` | `approval_not_required` | The evaluated manifest and caller policy did not require approval. This is not a positive applicability verdict. |

The legacy result is not a separate historical-authenticity verdict: for example,
`EXPIRED` can be returned for malformed timestamps before signature verification.
Approval duration sets a time window, not continuing authority. A signed
`previous_manifest_id` link alone does not establish current applicability either.

This additive SDK reporting field does not change approval enforcement or the
overall verification result. An overall `VALID` result can therefore coexist with
`UNDECIDABLE` applicability. Callers requiring present applicability must apply
their own evidence policy; they cannot treat `UNDECIDABLE` as permission to proceed.
The field adds no manifest approval fields or normative specification requirements.

## The 10 Attested Artifacts

| # | Artifact | What it proves |
|---|----------|---------------|
| 1 | System Prompt | The exact prompt that defines the agent's persona and safety constraints |
| 2 | Policy Bundle | The Cedar/Rego/YAML governance rules that were in force |
| 3 | Tool Manifest | Every tool schema and description the agent was authorized to call |
| 4 | Model Identity | Which model and version ran (binary hash for local, version for API) |
| 5 | RAG Corpus | The knowledge base the agent was grounded on (Merkle root) |
| 6 | Memory Baseline | Approved agent memory state with TTL-based re-approval |
| 7 | Decision-log baseline | Audit-chain root at manifest issuance; runtime decisions remain separate linked evidence |
| 8 | A2A Delegation | Signed delegation chain from human principal to current agent |
| 9 | Supply Chain | Container digest, SLSA provenance, SBOM, MCP server supply chain |
| 10 | HITL Approvals | Hardware-signed human oversight records (EU AI Act Art. 14) |

## Hardware Attestation

```python
from agent_manifest._auto_provider import select_provider

# auto-selects: SEV-SNP → TDX → TPM → software  (OPAQUE is explicit opt-in via OPAQUE_ATTESTATION_URL)
provider = select_provider(level=1)   # Level 1+ requires hardware
provider.extend_manifest_hash(manifest_dict)
report = provider.get_attestation_report()
# report.platform: "amd-sev-snp" | "intel-tdx" | "tpm" | "opaque" | "software"
```

| Provider | Hardware | Level | Install |
|----------|----------|-------|---------|
| `TPMProvider` | TPM 2.0 / AWS Nitro | 1 | `apt install tpm2-tools` |
| `SEVSNPProvider` | AMD SEV-SNP | 2 | Needs `/dev/sev-guest` |
| `TDXProvider` | Intel TDX | 2 | Needs `/dev/tdx-guest` |
| `OPAQUEProvider` | OPAQUE Runtime | 3 | Set `OPAQUE_ATTESTATION_URL` |

## Verification

```python
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore

result = verify_manifest(
    manifest_dict,
    VerificationContext(
        system_prompt_hash="sha256:...",
        policy_bundle_hash="sha256:...",
        enforce_hitl=True,
    ),
    RevocationStore(),
)
print(result.result)   # VALID | MISMATCH | EXPIRED | REVOKED | ...
```

## CLI

```bash
pip install "agent-manifest[cli]"

manifest keygen -d ./keys/
manifest create config.json -o draft.json
manifest sign draft.json --key keys/private.hex -o signed.json
manifest attest signed.json --provider auto --level 1 -o attested.json
manifest verify attested.json --public-key keys/public.hex
manifest revoke <manifest-id> --reason "key compromise" --revoked-by security@example.com
```

Without `--public-key` the verifier has no trusted issuer key, so a signed
manifest fails closed as `UNVERIFIABLE` and the command exits 1.

## Cryptography

- **Standard profile**: Ed25519 (RFC 8032), SHA-256, RFC 8785 canonical JSON
- **Post-quantum profile**: ML-DSA-65 (NIST FIPS 204), SHAKE-256  -  `pip install "agent-manifest[pq]"`
- **Hybrid**: Both signatures required, identical pre-image
- **Transparency**: Rekor/Sigstore integration for non-repudiation

## Specification

The full Agent Manifest Specification v0.2 is at [`spec/agent-manifest-spec-v0.2.md`](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.2.md).

Proposed for contribution to [CoSAI](https://www.coalitionforsecureai.org/) Working Stream 4, an OASIS Open Project.

## License

Apache 2.0
