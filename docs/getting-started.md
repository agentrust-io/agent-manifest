# Getting Started

This guide walks through creating, signing, and verifying an Agent Manifest in under 15 minutes. It covers Level 0 (software-only signing) and Level 1 (TPM-attested).

## Prerequisites

- Python 3.11 or later
- For Level 1: a Linux host with TPM 2.0 (`tpm2-tools` installed), an AMD SEV-SNP VM, or an Intel TDX VM

## Installation

```bash
# Core SDK
pip install agent-manifest

# With CLI
pip install "agent-manifest[cli]"

# With post-quantum profile
pip install "agent-manifest[pq]"
```

## Level 0 — Software-only signing

Level 0 is suitable for development, staging, and non-regulated environments. No hardware required.

### Step 1: Generate a signing key

```bash
manifest keygen -d ./keys/
# Creates keys/private.hex and keys/public.hex
```

Or in Python:

```python
from agent_manifest import generate_ed25519

keypair = generate_ed25519()
# Store keypair.private_hex and keypair.public_hex securely
```

### Step 2: Build the manifest

```python
from agent_manifest import (
    Manifest, ArtifactBindings,
    SystemPromptBinding, PolicyBundleBinding,
    ToolManifestBinding, ModelIdentityBinding,
    CryptoProfile, DeploymentType, EnforcementMode, PolicyLanguage,
)
from agent_manifest._types import HashValue, ManifestId
from datetime import datetime, timedelta, timezone
import hashlib

now = datetime.now(timezone.utc)

# Hash your actual artifacts
system_prompt_text = "You are a document summarization assistant..."
prompt_hash = "sha256:" + hashlib.sha256(
    system_prompt_text.encode("utf-8")
).hexdigest()

manifest = Manifest(
    manifest_id=ManifestId("019236ab-cdef-7000-8000-000000000001"),
    agent_id="spiffe://trust.acme.co/agent/doc-summarizer/prod",
    issued_at=now,
    expires_at=now + timedelta(days=90),
    issuer="spiffe://trust.acme.co/signing-authority",
    crypto_profile=CryptoProfile.standard,
    artifacts=ArtifactBindings(
        system_prompt=SystemPromptBinding(
            hash=HashValue(prompt_hash),
            hash_algorithm="SHA-256",
            version="1.0.0",
            classification="internal",
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
            model_id="claude-haiku-4-5-20251001",
            version="20251001",
            deployment_type=DeploymentType.api,
            bound_at=now,
        ),
    ),
)
```

### Step 3: Sign the manifest

```python
from agent_manifest import Ed25519Signer, generate_ed25519

keypair = generate_ed25519()
signer = Ed25519Signer(keypair)
manifest_dict = manifest.model_dump(mode="json", by_alias=True)
sig_block = signer.sign(manifest_dict)

manifest_dict["signature"] = sig_block
print(sig_block["algorithm"])  # Ed25519
```

Or with the CLI:

```bash
manifest create my-agent-config.json -o draft.json
manifest sign draft.json --key keys/private.hex -o signed.json
```

### Step 4: Verify

```python
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore

result = verify_manifest(
    manifest_dict,
    VerificationContext(
        system_prompt_hash=prompt_hash,
        policy_bundle_hash="sha256:" + "b" * 64,
    ),
    RevocationStore(),
)
print(result.result)   # VALID
```

Or with the CLI:

```bash
manifest verify signed.json
```

## Level 1 — TPM attestation

Level 1 adds hardware attestation, which binds the manifest hash to a TEE measurement that cannot be forged by the operator. Required for EU AI Act Art. 15 (cybersecurity) and enterprise production deployments.

### Prerequisites

On Ubuntu/Debian:

```bash
apt install tpm2-tools
```

On AWS: Nitro Enclaves with `aws-nitro-enclaves-sdk-python` installed.

### Attest the signed manifest

```python
from agent_manifest._auto_provider import select_provider

# Auto-selects: OPAQUE -> SEV-SNP -> TDX -> TPM -> Software
provider = select_provider(level=1)
provider.extend_manifest_hash(manifest_dict)
report = provider.get_attestation_report()

manifest_dict["attestation"] = {
    "tee_type": report.platform,       # "tpm" | "amd-sev-snp" | "intel-tdx" | "opaque"
    "manifest_hash_in_report": True,
    "report_uri": report.report_uri,
    "bound_at": now.isoformat(),
}
```

Or with the CLI:

```bash
manifest attest signed.json --provider auto --level 1 -o attested.json
manifest verify attested.json
```

The verification result for a Level 1 manifest includes `attestation_verified: true` when the TEE measurement matches the manifest hash.

## Revocation

When an artifact changes (new model version, policy update, system prompt revision), revoke the old manifest and issue a new one:

```bash
manifest revoke <manifest-id> \
  --reason "policy bundle updated to v1.1.0" \
  --revoked-by security@acme.co
```

In Python:

```python
from agent_manifest._verify import RevocationStore

store = RevocationStore()
store.revoke(
    manifest_id="019236ab-cdef-7000-8000-000000000001",
    reason="policy bundle updated to v1.1.0",
    revoked_by="security@acme.co",
)
```

## Next steps

- Read the [full specification](https://github.com/agentrust-io/agent-manifest/blob/main/spec/agent-manifest-spec-v0.1.md)
- Browse the [examples](../examples/) for complete manifest JSON for each conformance level
- For hardware attestation setup on Azure, AWS, or GCP, see the platform-specific notes in Section 3.3.1 of the spec
- For EU AI Act HITL compliance, see Section 9.1 and the Level 2 example in `examples/`
- For post-quantum signing, install `agent-manifest[pq]` and set `crypto_profile=CryptoProfile.post_quantum`
