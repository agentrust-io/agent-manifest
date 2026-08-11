"""Smoke-test an installed agent-manifest distribution outside the checkout."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from importlib.metadata import version
from pathlib import Path

import agent_manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--forbidden-source-root", required=True, type=Path)
    args = parser.parse_args()

    installed_version = version("agent-manifest")
    if installed_version != args.expected_version:
        raise SystemExit(
            f"installed version {installed_version!r} != expected {args.expected_version!r}"
        )

    module_path = Path(agent_manifest.__file__).resolve()
    forbidden_root = args.forbidden_source_root.resolve()
    if module_path.is_relative_to(forbidden_root):
        raise SystemExit(
            f"smoke test imported checkout source {module_path}, not the distribution"
        )

    now = datetime.now(timezone.utc)
    prompt_hash = "sha256:" + "a" * 64
    policy_hash = "sha256:" + "b" * 64
    keypair = agent_manifest.generate_ed25519()
    manifest = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/release-smoke/prod",
        "issuer": "spiffe://trust.example/issuer/release",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": prompt_hash},
            "policy_bundle": {
                "hash": policy_hash,
                "enforcement_mode": "enforce",
            },
            "model_identity": {
                "version": "release-smoke",
                "deployment_type": "api",
            },
        },
    }
    manifest["signature"] = agent_manifest.Ed25519Signer(keypair).sign(manifest)
    context = agent_manifest.VerificationContext(
        system_prompt_hash=prompt_hash,
        policy_bundle_hash=policy_hash,
        model_version="release-smoke",
        trusted_keys={keypair.key_id: keypair.public_b64url()},
    )
    result = agent_manifest.verify_manifest(
        manifest, context, agent_manifest.RevocationStore()
    )
    if result.result != agent_manifest.OverallResult.VALID:
        raise SystemExit(f"installed-package verification roundtrip failed: {result}")

    print(f"verified agent-manifest {installed_version} from {module_path}")


if __name__ == "__main__":
    main()
