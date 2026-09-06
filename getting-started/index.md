# Create and check your first manifest

Sign a small agent configuration, verify its declared inputs, then see two failures: an edited signed record and a different prompt hash. This software example runs locally after installation. It does not run a model or produce hardware attestation.

## Prerequisites

Use Python 3.11+, Git, and Bash on Linux, macOS, or Windows with WSL. This guide uses the current source checkout so its verification behavior matches these docs.

## Installation

```
git clone https://github.com/agentrust-io/agent-manifest.git manifest-quickstart
cd manifest-quickstart
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e "./python[cli]"
```

## Level 0 - Software-only signing

Save this complete block as `first_manifest.py`, then run `python first_manifest.py` from the same directory. It uses the supported v0.1 JSON form to make the signed fields readable. The current v0.2 envelope uses COSE; see the [signature envelope decision](https://manifest.agentrust-io.com/adr/0011-signature-envelope/index.md).

```
import copy
import json
from pathlib import Path

from agent_manifest import (
    Manifest, ArtifactBindings,
    SystemPromptBinding, PolicyBundleBinding,
    ModelIdentityBinding,
    CryptoProfile, DeploymentType, EnforcementMode, ModelAttestationType,
    PolicyLanguage,
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
            provider="example",
            model_id="demo-model",
            version="demo-v1",
            deployment_type=DeploymentType.api,
            model_attestation_type=ModelAttestationType.provider_asserted,
            bound_at=now,
        ),
    ),
)

from agent_manifest import Ed25519Signer, generate_ed25519
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore

keypair = generate_ed25519()
record = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
record["signature"] = Ed25519Signer(keypair).sign(record)
# Verifier inputs come from this demo's approved configuration, not the record.
context = VerificationContext(
    system_prompt_hash=prompt_hash,
    policy_bundle_hash="sha256:" + "b" * 64,
    enforcement_mode="enforce",
    model_version="demo-v1",
    trusted_keys={keypair.key_id: keypair.public_b64url()},
)
result = verify_manifest(record, context, RevocationStore())
assert result.result.value == "VALID", result.model_dump_json()
print("PASS: approved demo inputs match (VALID)")

changed = copy.deepcopy(record)
changed["artifacts"]["model_identity"]["version"] = "changed"
result = verify_manifest(changed, context, RevocationStore())
assert result.result.value == "MISMATCH" and not result.signature_verified
print("PASS: edited signed record rejected (MISMATCH)")

drift = context.model_copy(update={"system_prompt_hash": "sha256:" + "0" * 64})
result = verify_manifest(record, drift, RevocationStore())
assert result.result.value == "MISMATCH" and result.signature_verified
print("PASS: different prompt hash rejected (MISMATCH)")

Path("signed.json").write_text(json.dumps(record, indent=2))
Path("public.hex").write_text(keypair.public_bytes.hex())
print("Saved signed.json and public.hex; private key was not saved")
```

Expected output:

```
PASS: approved demo inputs match (VALID)
PASS: edited signed record rejected (MISMATCH)
PASS: different prompt hash rejected (MISMATCH)
Saved signed.json and public.hex; private key was not saved
```

The prompt hash comes from the demo text. The policy hash and model identity are synthetic declarations. `VALID` here applies to the three declared bindings and the supplied verifier inputs. It is not a claim that all ten artifact categories were bound, a model executed, or the configuration is safe.

The verifier retains its trusted public key separately from the record. In production, obtain issuer keys and runtime measurements through your approved trust channels. Reading expected hashes from an untrusted manifest would only compare the document with itself.

## Inspect the saved record

```
manifest verify signed.json --public-key public.hex
```

This CLI invocation supplies a trusted key but no runtime hashes. Expect `INCOMPLETE`, with a verified signature and missing artifact comparisons. Without `--public-key`, expect `UNVERIFIABLE`. The Python example supplies the comparison inputs needed for its `VALID` result.

## Level 1 - TPM attestation

Hardware provenance is a separate step. Follow the [hardware attestation tutorial](https://manifest.agentrust-io.com/tutorials/hardware-attestation/index.md) and [limitations](https://manifest.agentrust-io.com/limitations/index.md) for provider-specific evidence and appraisal. A TPM supplies measured-state evidence; it does not by itself isolate process memory. A declared hardware platform or a successful signing command does not establish a conformance level.

## Revocation

An artifact update needs a newly approved manifest. Production verification also needs current revocation information; this demo uses an empty in-memory store. See [revocation and key rotation](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md).

## Troubleshooting

- **Module not found:** activate `.venv` in the terminal running the example.
- **File not found:** run `first_manifest.py` before inspecting `signed.json`.
- **INCOMPLETE:** inspect which runtime comparisons are missing. Supply independent inputs instead of disabling strict verification.
- **MISMATCH:** check the signature and named artifact mismatch. Both deliberate changes in this demo should fail.
- **Expired record:** rerun the example to create a fresh demo record.

## Next steps

- [Specification](https://manifest.agentrust-io.com/spec/agent-manifest-v0.2/index.md): artifact and verification contracts.
- [cMCP session binding](https://manifest.agentrust-io.com/tutorials/cmcp-session-binding/index.md): connect deployment identity to tool-call evidence.
- [Verification API](https://manifest.agentrust-io.com/api-reference/index.md): caller inputs and result fields.
