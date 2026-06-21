# Your First Agent Manifest

By the end of this tutorial you will have a signed, schema-valid Agent Manifest that passes `verify_manifest()` with `OverallResult.VALID`.

## What you'll learn

- Generate an Ed25519 key pair with `generate_ed25519()`
- Construct a minimal manifest dict and understand which fields get signed
- Sign the manifest and add the signature block
- Validate the schema with `Manifest.model_validate()`
- Verify the signed manifest end-to-end

## Prerequisites

```bash
pip install agent-manifest
```

---

## Generate a key pair

`generate_ed25519()` returns an `Ed25519KeyPair`. The private key stays in memory; you will need the public key later to verify.

```python
from agent_manifest import generate_ed25519

kp = generate_ed25519()

print(kp.key_id)           # sha256 hex of the raw public key bytes
print(kp.public_b64url())  # base64url-encoded public key (no padding)
print(kp.private_b64url()) # base64url-encoded private key - keep secret
```

Store `kp.private_b64url()` in a secret manager (GitHub Actions secret, Vault, etc.). Never commit it to source control.

---

## Construct the manifest dict

A minimal manifest requires `manifest_id`, `agent_id`, `version`, `issued_at`, `expires_at`, `issuer`, and `artifacts`. All timestamps must be ISO 8601 UTC.

```python
from datetime import datetime, timedelta, timezone

now = datetime.now(timezone.utc)

manifest_dict = {
    "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",  # UUID v7
    "agent_id":    "spiffe://trust.example/agent/my-agent/prod",
    "version":     "0.1",
    "issued_at":   now.isoformat(),
    "expires_at":  (now + timedelta(hours=24)).isoformat(),
    "issuer":      "spiffe://trust.example/signing-authority",
    "artifacts":   {},
}
```

Use a real UUID v7 in production. You can generate one with `ManifestId.generate()`:

```python
from agent_manifest._types import ManifestId

manifest_dict["manifest_id"] = str(ManifestId.generate())
```

---

## Understand which fields get signed

`SIGNED_FIELDS` is the normative list of fields that are included in the signing pre-image. Fields outside this list (such as `signature` itself) are deliberately excluded so they can be added after signing.

```python
from agent_manifest import SIGNED_FIELDS

print(SIGNED_FIELDS)
# ('@context', '@type', 'manifest_id', 'previous_manifest_id', 'agent_id',
#  'version', 'min_verifier_version', 'issued_at', 'expires_at', 'issuer',
#  'crypto_profile', 'artifacts', 'delegation_chain', 'hitl_record',
#  'prior_transparency_log_entry', 'log_retention', 'data_scope',
#  'operational_lifecycle')
```

`signing_pre_image()` extracts those fields from your manifest dict and returns the RFC 8785 canonical JSON bytes:

```python
from agent_manifest import signing_pre_image

pre_image = signing_pre_image(manifest_dict)
print(type(pre_image))   # <class 'bytes'>
print(len(pre_image))    # canonical byte length varies by manifest size
```

The pre-image is what gets signed. Both the signer and the verifier call this same function to guarantee identical byte sequences.

---

## Sign the manifest

`Ed25519Signer.sign()` takes the manifest dict, computes the pre-image internally, and returns a signature block dict. Assign that block to `manifest_dict["signature"]`.

```python
from agent_manifest import Ed25519Signer

signer = Ed25519Signer(kp)
manifest_dict["signature"] = signer.sign(manifest_dict)

print(manifest_dict["signature"])
# {
#   "algorithm": "Ed25519",
#   "key_id": "<sha256 hex>",
#   "key_type": "software",
#   "signed_at": "2026-06-21T...",
#   "signature_value": "<base64url>",
#   "signed_fields": [...]
# }
```

---

## Validate the schema

`Manifest.model_validate()` checks that the manifest conforms to the Pydantic schema. It raises `ValidationError` if any required field is missing or any value has the wrong type.

```python
from agent_manifest import Manifest

manifest_obj = Manifest.model_validate(manifest_dict)
print(manifest_obj.manifest_id)
print(manifest_obj.agent_id)
```

Schema validation is separate from signature verification. A manifest can be schema-valid but have an invalid signature, and vice versa.

---

## Verify the signed manifest

`verify_manifest()` takes the manifest dict, a `VerificationContext`, and a `RevocationStore`. It returns a `VerificationResult` with an `OverallResult` enum.

To get `OverallResult.VALID` you must supply the signer's public key in `trusted_keys`. Without it the result is `UNVERIFIABLE` - the verifier cannot authenticate the manifest.

```python
from agent_manifest import (
    verify_manifest,
    VerificationContext,
    RevocationStore,
    OverallResult,
)

ctx = VerificationContext(
    trusted_keys={kp.key_id: kp.public_b64url()},
)

result = verify_manifest(manifest_dict, ctx, RevocationStore())

assert result.result == OverallResult.VALID
assert result.signature_verified is True
print(f"Result: {result.result}")           # VALID
print(f"Manifest ID: {result.manifest_id}")
```

If you omit `trusted_keys`, the verifier returns `UNVERIFIABLE`:

```python
ctx_no_keys = VerificationContext()
result = verify_manifest(manifest_dict, ctx_no_keys, RevocationStore())
assert result.result == OverallResult.UNVERIFIABLE
```

---

## Summary

You generated an Ed25519 key pair, built a minimal manifest dict, signed it with `Ed25519Signer`, validated the schema with `Manifest.model_validate()`, and verified it with `verify_manifest()`. The `SIGNED_FIELDS` tuple and `signing_pre_image()` are the canonical source of truth for what gets signed - both sides of the protocol call the same function. Next, see [CI/CD signing](ci-cd-signing.md) to automate this in a GitHub Actions workflow, or [HITL approval workflows](hitl-approval-workflows.md) to require human sign-off before a manifest can verify as valid.
