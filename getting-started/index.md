# Create and check your first manifest

This page is for anyone trying Agent Manifest for the first time. In about ten minutes you sign a record of a small sample agent, check it, and then watch the check fail twice on purpose: once when someone edits the signed record, and once when the agent's prompt changes.

Everything runs on your own computer. It does not run an AI model or produce a hardware report (attestation); those come later.

## Prerequisites

You need Python 3.11 or later, Git, and a Bash terminal on Linux, macOS, or Windows with WSL. The steps install from a copy of the source code, so the checks behave exactly as these docs describe.

## Installation

```
git clone https://github.com/agentrust-io/agent-manifest.git manifest-quickstart
cd manifest-quickstart
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e "./python[cli]"
```

## Level 0 - Software-only signing

Save this complete block as `first_manifest.py`, then run `python first_manifest.py` from the same directory. The script does four things: it takes a fingerprint (a SHA-256 hash) of a sample prompt, writes a manifest that records it, signs the manifest with a new key, and checks the result three ways.

It uses the older v0.1 JSON form because its signed fields are easy to read. The current v0.2 format wraps the same content in a compact binary envelope called COSE; see the [signature envelope decision](https://manifest.agentrust-io.com/adr/0011-signature-envelope/index.md).

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

What this shows: `VALID` means the signature checks out and the three parts recorded here match the values the checker was given. The prompt hash comes from the demo text; the policy hash and model details are made up for the demo. `VALID` does not mean all ten parts of an agent were recorded, that a model ran, or that the setup is safe.

The checker (verifier) keeps the trusted public key apart from the record. In a real deployment, get signer keys and the values of what is actually running from sources you already trust. Taking the expected values from the manifest itself would only compare the document with itself.

## Inspect the saved record

```
manifest verify signed.json --public-key public.hex
```

This command line check gets a trusted key but no values to compare against. Expect `INCOMPLETE`: the signature is verified, but the parts could not be compared. Without `--public-key`, expect `UNVERIFIABLE`, because there is no key to check the signature with. The Python script got `VALID` because it supplied the values to compare.

## Level 1 - TPM attestation

Proving which hardware the agent runs on is a separate step. Follow the [hardware attestation tutorial](https://manifest.agentrust-io.com/tutorials/hardware-attestation/index.md) and [limitations](https://manifest.agentrust-io.com/limitations/index.md) for how each kind of chip reports and how to judge its report. A TPM (a security chip found in most servers and laptops) reports what software the machine booted; it does not by itself keep the agent's memory private from the rest of the machine. Naming a hardware platform in the record, or a signing command succeeding, does not reach a conformance level.

## Revocation

If any recorded part changes, such as a new prompt, approve and sign a new manifest. A real checker also needs an up-to-date list of withdrawn (revoked) manifests and keys; this demo uses an empty list. See [revocation and key rotation](https://manifest.agentrust-io.com/tutorials/revocation-and-key-rotation/index.md).

## Troubleshooting

- **Module not found:** activate `.venv` in the terminal running the example.
- **File not found:** run `first_manifest.py` before inspecting `signed.json`.
- **INCOMPLETE:** look at which comparisons are missing and supply those values from a trusted source. Do not switch off strict checking to make it pass.
- **MISMATCH:** check whether the signature failed or a named part did not match. Both deliberate changes in this demo should fail.
- **Expired record:** rerun the example to create a fresh demo record.

## Next steps

- [Specification](https://manifest.agentrust-io.com/spec/agent-manifest-v0.2/index.md): the formal rules for each part and each check.
- [cMCP session binding](https://manifest.agentrust-io.com/tutorials/cmcp-session-binding/index.md): link the approved agent to the records of its tool calls.
- [Verification API](https://manifest.agentrust-io.com/api-reference/index.md): what you pass to the checker and what it returns.
