"""Public API surface: the relying-party verification engine must be importable
from the package root, not only from the private agent_manifest._verify module.

This closes the verification-contract gap raised in agent-manifest#175 (and seen
in the cMCP integration, agentrust-io/cmcp#302): a relying party should call
agent_manifest.verify_manifest rather than reach into a private module or
reimplement the canonical pre-image. The roundtrip exercises the same VALID and
MISMATCH paths as AM-VERIFY-07 / AM-VERIFY-11 through the public import path.
"""
from datetime import datetime, timedelta, timezone

import agent_manifest

_PUBLIC_VERIFY_API = (
    "verify_manifest",
    "VerificationContext",
    "VerificationResult",
    "OverallResult",
    "FieldResult",
    "DelegationResult",
    "HitlResult",
    "FieldsVerified",
    "MismatchDetail",
    "EvidencePack",
    "RevocationStore",
    "RevocationRecord",
)


def _signed_manifest(keypair):
    now = datetime.now(timezone.utc)
    sha_a = "sha256:" + "a" * 64
    sha_b = "sha256:" + "b" * 64
    manifest = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": sha_a},
            "policy_bundle": {"hash": sha_b, "enforcement_mode": "enforce"},
            "model_identity": {"version": "claude-3", "deployment_type": "api"},
        },
    }
    manifest["signature"] = agent_manifest.Ed25519Signer(keypair).sign(manifest)
    return manifest, sha_a, sha_b


def test_relying_party_api_is_exported_from_package_root():
    for name in _PUBLIC_VERIFY_API:
        assert name in agent_manifest.__all__, f"{name} missing from __all__"
        assert hasattr(agent_manifest, name), f"{name} not importable from package root"


def test_public_verify_roundtrip_valid_then_mismatch():
    keypair = agent_manifest.generate_ed25519()
    manifest, sha_a, sha_b = _signed_manifest(keypair)
    trusted = {keypair.key_id: keypair.public_b64url()}

    matching = agent_manifest.VerificationContext(
        system_prompt_hash=sha_a,
        policy_bundle_hash=sha_b,
        model_version="claude-3",
        trusted_keys=trusted,
    )
    valid = agent_manifest.verify_manifest(
        manifest, matching, agent_manifest.RevocationStore()
    )
    assert valid.result == agent_manifest.OverallResult.VALID

    drifted = agent_manifest.VerificationContext(
        system_prompt_hash="sha256:" + "f" * 64,  # running prompt differs from manifest
        policy_bundle_hash=sha_b,
        model_version="claude-3",
        trusted_keys=trusted,
    )
    mismatch = agent_manifest.verify_manifest(
        manifest, drifted, agent_manifest.RevocationStore()
    )
    assert mismatch.result == agent_manifest.OverallResult.MISMATCH
