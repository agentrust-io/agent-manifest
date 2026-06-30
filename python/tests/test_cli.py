"""CLI tests for local manifest verification workflows."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from agent_manifest.cli import cli
from agent_manifest._signing import Ed25519Signer, generate_ed25519


def _signed_manifest(keypair):
    now = datetime.now(timezone.utc)
    manifest = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/cli-test/prod",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=90)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/signing-authority",
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {
                "hash": "sha256:" + "a" * 64,
                "hash_algorithm": "SHA-256",
                "version": "1.0.0",
                "classification": "internal",
                "bound_at": now.isoformat().replace("+00:00", "Z"),
            },
            "policy_bundle": {
                "hash": "sha256:" + "b" * 64,
                "policy_language": "cedar",
                "version": "1.0.0",
                "enforcement_mode": "enforce",
                "bound_at": now.isoformat().replace("+00:00", "Z"),
            },
            "model_identity": {
                "provider": "openai",
                "model_id": "gpt-4o",
                "version": "gpt-4o-2024-08-06",
                "deployment_type": "api",
                "model_attestation_type": "provider-asserted",
                "bound_at": now.isoformat().replace("+00:00", "Z"),
            },
        },
    }
    manifest["signature"] = Ed25519Signer(keypair).sign(manifest)
    return manifest


def _write_signed_manifest(tmp_path: Path, keypair) -> Path:
    signed_path = tmp_path / "signed.json"
    signed_path.write_text(json.dumps(_signed_manifest(keypair)))
    return signed_path


def _write_public_key(tmp_path: Path, keypair, name: str = "public.hex") -> Path:
    public_path = tmp_path / name
    public_path.write_text(keypair.public_bytes.hex())
    return public_path


def _json_stdout(result):
    return json.loads(result.stdout)


def test_cli_verify_without_public_key_is_unverifiable(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)

    result = CliRunner().invoke(cli, ["manifest", "verify", str(signed_path)])

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["result"] == "UNVERIFIABLE"
    assert payload["signature_verified"] is False


def test_cli_verify_with_matching_public_key_is_valid(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)

    result = CliRunner().invoke(
        cli,
        ["manifest", "verify", str(signed_path), "--public-key", str(public_path)],
    )

    payload = _json_stdout(result)
    assert result.exit_code == 0
    assert payload["result"] == "VALID"
    assert payload["signature_verified"] is True


def test_cli_verify_with_wrong_public_key_is_mismatch(tmp_path):
    keypair = generate_ed25519()
    wrong_keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, wrong_keypair, "wrong-public.hex")

    result = CliRunner().invoke(
        cli,
        ["manifest", "verify", str(signed_path), "--public-key", str(public_path)],
    )

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["result"] == "MISMATCH"
    assert any(d["field"] == "signature" for d in payload["mismatch_details"])


def test_cli_verify_with_malformed_public_key_fails_cleanly(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = tmp_path / "bad.hex"
    public_path.write_text("not-hex")

    result = CliRunner().invoke(
        cli,
        ["manifest", "verify", str(signed_path), "--public-key", str(public_path)],
    )

    assert result.exit_code != 0
    assert "Public key file does not contain valid hex data." in result.output
    assert "Traceback" not in result.output


def test_cli_verify_with_missing_public_key_file_fails_cleanly(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = tmp_path / "missing.hex"

    result = CliRunner().invoke(
        cli,
        ["manifest", "verify", str(signed_path), "--public-key", str(public_path)],
    )

    assert result.exit_code != 0
    assert "Public key file not found or is not a regular file" in result.output
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Fix #4: CLI must be honest when artifacts are bound but not checked
# ---------------------------------------------------------------------------


def test_cli_verify_bound_artifacts_without_runtime_hashes_qualifies_valid(tmp_path):
    # The manifest binds system_prompt and policy_bundle hashes, but the CLI
    # supplies no runtime hashes, so those bindings are never compared. The
    # output must qualify the VALID status and warn - never a bare "VALID".
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)

    result = CliRunner().invoke(
        cli,
        ["manifest", "verify", str(signed_path), "--public-key", str(public_path)],
    )

    # Signature is genuinely valid (exit 0), but the status must be qualified.
    assert result.exit_code == 0
    payload = _json_stdout(result)
    assert payload["result"] == "VALID"
    assert "VALID (signature only - artifact bindings NOT verified)" in result.output
    assert "WARNING" in result.output
    # The bare "Result: VALID" line must NOT be emitted in this case.
    assert "Result: VALID\n" not in result.output
    # And the result payload carries the machine-readable warning too.
    assert any("artifact bindings NOT verified" in w for w in payload["warnings"])
