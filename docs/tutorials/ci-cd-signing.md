# CI/CD Signing

By the end of this tutorial you will have a GitHub Actions workflow that signs an Agent Manifest on every release, verifies the signature as a build gate, and documents the key rotation procedure.

## What you'll learn

- Generate a signing key pair once and store the private key as a GitHub secret
- Sign a manifest in a GitHub Actions workflow
- Verify the signature as a required CI step (fail the build if invalid)
- Rotate the signing key without downtime

## Prerequisites

```bash
pip install agent-manifest
```

---

## Generate the keypair once

Run this locally to generate the keypair. Copy the private key output into a GitHub secret. Keep the public key - you will need it in verifying systems and for key rotation.

```python
from agent_manifest import generate_ed25519

kp = generate_ed25519()
print("Private key (store as GitHub secret MANIFEST_SIGNING_KEY):")
print(kp.private_b64url())
print()
print("Public key (add to relying party trusted_keys):")
print(kp.public_b64url())
print()
print("Key ID (sha256 of public key bytes):")
print(kp.key_id)
```

Or from the command line:

```bash
python -c "
from agent_manifest import generate_ed25519
kp = generate_ed25519()
print('PRIVATE:', kp.private_b64url())
print('PUBLIC: ', kp.public_b64url())
print('KEY_ID: ', kp.key_id)
"
```

Store `MANIFEST_SIGNING_KEY` and `MANIFEST_PUBLIC_KEY` in your repository's Actions secrets (`Settings > Secrets and variables > Actions > New repository secret`). Never commit either value to the repo.

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

from agent_manifest import generate_ed25519, Ed25519Signer
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

    ctx = VerificationContext(
        trusted_keys={key_id: public_b64url},
    )
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

      - name: Verify the signature
        env:
          MANIFEST_PUBLIC_KEY: ${{ secrets.MANIFEST_PUBLIC_KEY }}
          MANIFEST_KEY_ID: ${{ secrets.MANIFEST_KEY_ID }}
        run: python scripts/verify_manifest.py signed-agent-manifest.json

      - name: Commit the signed manifest
        run: |
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add signed-agent-manifest.json
          git diff --staged --quiet || git commit -m "chore: update signed agent manifest [skip ci]"
          git push
```

The `verify` step acts as a build gate: if the signature is invalid, the workflow fails before the commit step runs.

---

## Key rotation

Rotate the signing key when it is compromised, expiring, or when ownership changes. The procedure:

1. Generate a new keypair (run the generation command above locally).
2. Update the GitHub secrets `MANIFEST_SIGNING_KEY`, `MANIFEST_PUBLIC_KEY`, and `MANIFEST_KEY_ID` with the new values.
3. Re-run the signing workflow to produce a new signed manifest with the new key.
4. Update the `trusted_keys` map in every relying party that verifies your manifests to include the new key ID.
5. Revoke all manifests signed by the old key. See [Revocation and key rotation](revocation-and-key-rotation.md).
6. Remove the old key ID from relying party `trusted_keys` after a short overlap period.

Never update the GitHub secret in place without completing step 4 first - verifiers holding only the old key ID will start returning `UNVERIFIABLE` the moment the secret changes.

---

## Summary

You stored the private key as a GitHub Actions secret, automated signing in CI, and added a verification gate that fails the build if the signature is invalid. The public key and key ID are the values you distribute to relying parties; the private key never leaves the secret store. For key compromise procedures, see [Revocation and key rotation](revocation-and-key-rotation.md). For the first-time setup walkthrough, see [Your first manifest](your-first-manifest.md).
