# agent-manifest

**Cryptographically anchor all 10 artifacts defining an AI agent at deployment.**

The Agent Manifest SDK implements the Agent Manifest Specification v0.1 — a hardware-attestable document that binds every artifact defining an agent's behavior (system prompt, policy bundle, tool schemas, model identity, RAG corpus, memory state, audit chain, delegation chain, supply chain, and human approvals) into a single tamper-evident identity primitive.

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
sig_block = signer.sign(manifest.model_dump(mode="json", by_alias=True))
print(sig_block["algorithm"])   # Ed25519
print(sig_block["key_id"])      # sha256:<hex>
```

## The 10 Attested Artifacts

| # | Artifact | What it proves |
|---|----------|---------------|
| 1 | System Prompt | The exact prompt that defines the agent's persona and safety constraints |
| 2 | Policy Bundle | The Cedar/Rego/YAML governance rules that were in force |
| 3 | Tool Manifest | Every tool schema and description the agent was authorized to call |
| 4 | Model Identity | Which model and version ran (binary hash for local, version for API) |
| 5 | RAG Corpus | The knowledge base the agent was grounded on (Merkle root) |
| 6 | Memory Baseline | Approved agent memory state with TTL-based re-approval |
| 7 | Decision Trace | Hardware-signed audit chain root for all agent decisions |
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
| `OPAQUEProvider` | Opaque Runtime | 3 | Set `OPAQUE_ATTESTATION_URL` |

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
manifest verify attested.json
manifest revoke <manifest-id> --reason "key compromise" --revoked-by security@example.com
```

## Cryptography

- **Standard profile**: Ed25519 (RFC 8032), SHA-256, RFC 8785 canonical JSON
- **Post-quantum profile**: ML-DSA-65 (NIST FIPS 204), SHAKE-256 — `pip install "agent-manifest[pq]"`
- **Hybrid**: Both signatures required, identical pre-image
- **Transparency**: Rekor/Sigstore integration for non-repudiation

## Specification

The full Agent Manifest Specification v0.1 is at [`spec/agent-manifest-spec-v0.1.md`](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.1.md).

Being submitted to the [Agentic AI Foundation (AAIF)](https://agenticai.foundation) under the Linux Foundation alongside AGT.

## License

Apache 2.0
