# CI/CD Signing

Sign an Agent Manifest when its source file changes on `main`, then reject it if it does not match the verifier's approved runtime inputs. This guide provides both Python scripts, a GitHub Actions workflow, and the key rotation sequence.

## What you'll learn

- Generate a signing key pair once and store the private key as a GitHub secret
- Sign a manifest in a GitHub Actions workflow
- Require a `VALID` verification result as a CI step
- Rotate the signing key using an explicit trust-distribution procedure

## Prerequisites

```bash
pip install agent-manifest
```

---

## Generate the keypair once

Generate the issuer key through your approved key-management system. For a local development key, `manifest keygen -d keys/` writes key files rather than printing the private key. Keep private files out of source control and logs.

Provision `MANIFEST_SIGNING_KEY` as base64url-encoded raw Ed25519 private bytes using your secret-management process. Configure `MANIFEST_PUBLIC_KEY` (base64url public bytes) and `MANIFEST_KEY_ID` independently on the verifier. The public key is not secret, but its integrity matters. The example workflow below references all three as Actions secrets.

Provide `approved-context.json` containing the recipient's approved runtime observations using the fields of `VerificationContext`, such as prompt and policy hashes, enforcement mode, and model version. Maintain it under the verifier's change controls; do not generate expected values by copying them from the incoming manifest. Missing required observations can produce `INCOMPLETE` even when the signature is valid.

---

## Write the signing script

Create `scripts/sign_manifest.py` in your repo. The workflow will call this script.

```python
# scripts/sign_manifest.py
import json
import os
import sys
from base64 import urlsafe_b64decode
from pathlib import Path

from agent_manifest import Ed25519Signer
from agent_manifest._signing import ed25519_from_private_bytes


def main():
    manifest_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else manifest_path

    private_b64url = os.environ["MANIFEST_SIGNING_KEY"]
    # Decode base64url to raw bytes, then reconstruct the keypair
    pad = 4 - len(private_b64url) % 4
    raw = urlsafe_b64decode(private_b64url + ("=" * pad if pad != 4 else ""))
    kp = ed25519_from_private_bytes(raw)

    with open(manifest_path) as f:
        manifest_dict = json.load(f)

    # Strip any existing signature before re-signing
    manifest_dict.pop("signature", None)

    signer = Ed25519Signer(kp)
    manifest_dict["signature"] = signer.sign(manifest_dict)

    with open(output_path, "w") as f:
        json.dump(manifest_dict, f, indent=2)

    print(f"Signed: {manifest_dict['manifest_id']}")
    print(f"Key ID: {manifest_dict['signature']['key_id']}")


if __name__ == "__main__":
    main()
```

---

## Write the verification script

Create `scripts/verify_manifest.py`. This script exits with code 1 if verification fails - GitHub Actions treats a non-zero exit code as a build failure.

```python
# scripts/verify_manifest.py
import json
import os
import sys
from pathlib import Path

from agent_manifest import verify_manifest, VerificationContext, RevocationStore, OverallResult


def main():
    manifest_path = Path(sys.argv[1])
    public_b64url = os.environ["MANIFEST_PUBLIC_KEY"]
    key_id = os.environ["MANIFEST_KEY_ID"]

    with open(manifest_path) as f:
        manifest_dict = json.load(f)

    context_path = Path(os.environ["MANIFEST_CONTEXT_FILE"])
    approved_inputs = json.loads(context_path.read_text())
    # Trust is configured here, never selected by the received manifest.
    approved_inputs["trusted_keys"] = {key_id: public_b64url}
    ctx = VerificationContext.model_validate(approved_inputs)
    result = verify_manifest(manifest_dict, ctx, RevocationStore())

    if result.result != OverallResult.VALID:
        print(f"FAIL: {result.result}", file=sys.stderr)
        for detail in result.mismatch_details:
            print(f"  {detail.field}: expected {detail.expected_hash}, got {detail.actual_hash}", file=sys.stderr)
        sys.exit(1)

    print(f"OK: {result.manifest_id} verified ({result.result})")


if __name__ == "__main__":
    main()
```

---

## GitHub Actions workflow

```yaml
# .github/workflows/sign-manifest.yml
name: Sign and verify agent manifest

on:
  push:
    branches: [main]
    paths:
      - "agent-manifest.json"
  workflow_dispatch:

jobs:
  sign:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.12"

      - name: Install agent-manifest
        run: pip install agent-manifest

      - name: Sign the manifest
        env:
          MANIFEST_SIGNING_KEY: ${{ secrets.MANIFEST_SIGNING_KEY }}
        run: python scripts/sign_manifest.py agent-manifest.json signed-agent-manifest.json

      - name: Verify the manifest against approved inputs
        env:
          MANIFEST_PUBLIC_KEY: ${{ secrets.MANIFEST_PUBLIC_KEY }}
          MANIFEST_KEY_ID: ${{ secrets.MANIFEST_KEY_ID }}
          MANIFEST_CONTEXT_FILE: approved-context.json
        run: python scripts/verify_manifest.py signed-agent-manifest.json

      - name: Commit the signed manifest
        run: |
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add signed-agent-manifest.json
          git diff --staged --quiet || git commit -m "chore: update signed agent manifest [skip ci]"
          git push
```

The `verify` step accepts only `VALID` with the configured runtime inputs. The empty `RevocationStore` in this build-only example performs no live revocation refresh; configure authenticated revocation state for a deployment acceptance gate. This example targets the v0.1 JSON format, not v0.2 COSE bytes. Protect the workflow, signing secrets, and approved-context file from untrusted changes before using it for release signing.

---

## Key rotation

Distribute and verify new public-key trust before switching a planned issuer key. Issue replacement manifests with new IDs when old IDs will be revoked, and refresh relying parties' revocation stores explicitly. A compromised key is not a safe overlap or rollback option. Follow the [key rotation runbook](../operations/key-rotation.md); availability depends on the rollout and has no fixed guarantee.

---

## Next steps

For key compromise procedures, see [Revocation and key rotation](revocation-and-key-rotation.md). For a local signing and verification walkthrough, see [Your first manifest](your-first-manifest.md).
