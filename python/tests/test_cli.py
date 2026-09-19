"""CLI tests for local manifest verification workflows."""
from __future__ import annotations

import json
import os
import stat
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_manifest.cli import cli
from agent_manifest._delegation import HitlApprovalSigner
from agent_manifest._revocation import FileCRL, sign_revocation
from agent_manifest._signing import Ed25519Signer, generate_ed25519

APPROVER_ID = "mailto:alice@example.com"


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

    result = CliRunner().invoke(cli, ["verify", str(signed_path)])

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
        [
            "verify", str(signed_path), "--public-key", str(public_path),
            "--signature-only",
        ],
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
        ["verify", str(signed_path), "--public-key", str(public_path)],
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
        ["verify", str(signed_path), "--public-key", str(public_path)],
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
        ["verify", str(signed_path), "--public-key", str(public_path)],
    )

    assert result.exit_code != 0
    assert "Public key file not found or is not a regular file" in result.output
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# CRL-CLI-001: --crl-path must be able to authenticate revocation records.
#
# FileCRL(trusted_signer_key=...) already verifies each record's signature
# (REVOC-003), but the CLI's `verify --crl-path` never plumbed that argument
# through, so every CLI-driven CRL load ran in FileCRL's unauthenticated
# "development mode" regardless of intent. A party who can write to or
# intercept the CRL file could inject a fabricated revocation record and the
# CLI would accept it. --crl-trusted-key authenticates present records; it
# cannot detect deletion of a complete record.
# ---------------------------------------------------------------------------


def _write_crl_with_revocation(tmp_path, manifest_id, authority_kp, name="crl.jsonl"):
    crl_path = tmp_path / name
    crl = FileCRL(crl_path, trusted_signer_key=authority_kp.public_bytes)
    crl.revoke(sign_revocation(manifest_id, "key compromise", "admin", authority_kp))
    return crl_path


def _write_authority_key(tmp_path, keypair, name="authority.hex") -> Path:
    path = tmp_path / name
    path.write_text(keypair.public_bytes.hex())
    return path


def test_cli_verify_crl_trusted_key_detects_revocation(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    authority_kp = generate_ed25519()
    manifest = json.loads(signed_path.read_text())
    crl_path = _write_crl_with_revocation(tmp_path, manifest["manifest_id"], authority_kp)
    authority_path = _write_authority_key(tmp_path, authority_kp)

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--signature-only",
            "--crl-path", str(crl_path),
            "--crl-trusted-key", str(authority_path),
        ],
    )

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["result"] == "REVOKED"
    assert "WARNING" not in result.output


def test_cli_verify_crl_without_trusted_key_still_works_but_warns(tmp_path):
    # Backward-compatible: omitting --crl-trusted-key must not break existing
    # scripts, but it must loudly say the CRL is unauthenticated.
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    authority_kp = generate_ed25519()
    manifest = json.loads(signed_path.read_text())
    crl_path = _write_crl_with_revocation(tmp_path, manifest["manifest_id"], authority_kp)

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--signature-only",
            "--crl-path", str(crl_path),
        ],
    )

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["result"] == "REVOKED"
    combined = (result.output or "") + (result.stderr or "")
    assert "WARNING: --crl-path given without --crl-trusted-key" in combined


def test_cli_verify_crl_with_wrong_trusted_key_fails_closed(tmp_path):
    # A CRL signed by an authority the caller does NOT trust must NOT be
    # treated as evidence of non-revocation. The record fails REVOC-003
    # verification on load, which must surface as a hard, non-zero-exit
    # error — not as a silent "not revoked" / VALID result. Reporting VALID
    # here would let anyone who can tamper with (or swap the signer of) a
    # record achieve the same un-revocation outcome --crl-trusted-key exists
    # to prevent (CRL-CLI-002).
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    real_authority = generate_ed25519()
    untrusted_authority = generate_ed25519()
    manifest = json.loads(signed_path.read_text())
    crl_path = _write_crl_with_revocation(
        tmp_path, manifest["manifest_id"], untrusted_authority
    )
    trusted_path = _write_authority_key(tmp_path, real_authority)

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--signature-only",
            "--crl-path", str(crl_path),
            "--crl-trusted-key", str(trusted_path),
        ],
    )
    assert result.exit_code != 0
    assert "CRL failed integrity verification" in result.output
    assert "Traceback" not in result.output
    # Must NOT be reachable as a VALID/REVOKED verdict in stdout — the
    # command must fail before verify_manifest() ever runs.
    assert '"result"' not in result.output


def test_cli_verify_crl_with_tampered_record_fails_closed(tmp_path):
    # Directly reproduces the reviewer's repro: flip a byte in a genuinely
    # signed record's signature and confirm the CLI errors out instead of
    # reporting the manifest as not revoked.
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    authority_kp = generate_ed25519()
    manifest = json.loads(signed_path.read_text())
    crl_path = _write_crl_with_revocation(
        tmp_path, manifest["manifest_id"], authority_kp
    )
    authority_path = _write_authority_key(tmp_path, authority_kp)

    line = json.loads(crl_path.read_text().splitlines()[0])
    sig = list(line["revocation_signature"])
    mid_idx = len(sig) // 2
    sig[mid_idx] = "A" if sig[mid_idx] != "A" else "B"
    line["revocation_signature"] = "".join(sig)
    crl_path.write_text(json.dumps(line) + "\n")

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--signature-only",
            "--crl-path", str(crl_path),
            "--crl-trusted-key", str(authority_path),
        ],
    )

    assert result.exit_code != 0
    assert "CRL failed integrity verification" in result.output
    assert "Traceback" not in result.output


def test_cli_verify_crl_cannot_detect_deleted_record(tmp_path):
    # Deleting a signed record entirely is currently indistinguishable from
    # "it never existed" (documented limitation see CHANGELOG/docs: this
    # is NOT fixed by fail-closed verification of present records, and
    # requires a signed CRL snapshot/digest to close). This test pins down
    # today's actual behavior so a future regression doesn't silently
    # loosen it further without anyone noticing.
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    authority_kp = generate_ed25519()
    manifest = json.loads(signed_path.read_text())
    crl_path = _write_crl_with_revocation(
        tmp_path, manifest["manifest_id"], authority_kp
    )
    authority_path = _write_authority_key(tmp_path, authority_kp)

    crl_path.write_text("")  # simulate deletion of the (only) record

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--signature-only",
            "--crl-path", str(crl_path),
            "--crl-trusted-key", str(authority_path),
        ],
    )
    payload = _json_stdout(result)
    assert result.exit_code == 0
    assert payload["result"] == "VALID"


def test_cli_verify_crl_trusted_key_without_crl_path_fails_cleanly(tmp_path):
    # --crl-trusted-key with no --crl-path has nothing to authenticate and
    # would otherwise be silently ignored, giving a false sense that
    # revocation checking is enabled when it is not running at all.
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    authority_kp = generate_ed25519()
    authority_path = _write_authority_key(tmp_path, authority_kp)

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--crl-trusted-key", str(authority_path),
        ],
    )

    assert result.exit_code != 0
    assert "--crl-trusted-key requires --crl-path." in result.output
    assert "Traceback" not in result.output


def test_cli_verify_crl_trusted_key_malformed_fails_cleanly(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)
    crl_path = tmp_path / "crl.jsonl"
    crl_path.write_text("")
    bad_authority_path = tmp_path / "bad-authority.hex"
    bad_authority_path.write_text("not-hex")

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path),
            "--public-key", str(public_path),
            "--crl-path", str(crl_path),
            "--crl-trusted-key", str(bad_authority_path),
        ],
    )

    assert result.exit_code != 0
    assert "CRL trusted key file does not contain valid hex data." in result.output
    assert "Traceback" not in result.output


# ---------------------------------------------------------------------------
# Fix #4: CLI must be honest when artifacts are bound but not checked
# ---------------------------------------------------------------------------


def test_cli_verify_bound_artifacts_without_runtime_hashes_is_incomplete(tmp_path):
    # The manifest binds system_prompt and policy_bundle hashes, but the CLI
    # supplies no runtime hashes, so those bindings are never compared. The
    # safe default must not turn signature validity into artifact validity.
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)

    result = CliRunner().invoke(
        cli,
        ["verify", str(signed_path), "--public-key", str(public_path)],
    )

    assert result.exit_code == 1
    payload = _json_stdout(result)
    assert payload["result"] == "INCOMPLETE"
    assert "Result: INCOMPLETE" in result.output
    assert any("artifact bindings NOT verified" in w for w in payload["warnings"])


def test_cli_required_transparency_missing_is_incomplete(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path), "--public-key", str(public_path),
            "--signature-only", "--require-transparency",
        ],
    )

    assert result.exit_code == 1
    payload = _json_stdout(result)
    assert payload["result"] == "INCOMPLETE"
    assert payload["transparency_verified"] is False


def test_cli_verified_legacy_transparency_entry_is_valid(tmp_path):
    keypair = generate_ed25519()
    manifest = _signed_manifest(keypair)
    entry_id = "rekor-cli-entry"
    manifest["transparency_log_entry"] = {
        "log_id": "0" * 64,
        "log_index": 1,
        "entry_uuid": entry_id,
        "integrated_time": 1,
        "inclusion_proof": {
            "checkpoint": "signed-checkpoint",
            "hashes": [],
            "tree_size": 1,
        },
    }
    signed_path = tmp_path / "signed-with-receipt.json"
    signed_path.write_text(json.dumps(manifest))
    public_path = _write_public_key(tmp_path, keypair)

    result = CliRunner().invoke(
        cli,
        [
            "verify", str(signed_path), "--public-key", str(public_path),
            "--signature-only", "--require-transparency",
            "--verified-transparency-entry-id", entry_id,
            "--transparency-evidence-manifest-id", manifest["manifest_id"],
        ],
    )

    assert result.exit_code == 0
    payload = _json_stdout(result)
    assert payload["result"] == "VALID"
    assert payload["transparency_verified"] is True


# ---------------------------------------------------------------------------
# Command surface: the documented invocation must be the real one
# ---------------------------------------------------------------------------


def test_documented_commands_are_top_level():
    # Releases up to 0.5.0 nested every command under a redundant `manifest`
    # group, so `manifest verify signed.json` (the form printed in the README,
    # the docs site, and the PyPI description) exited with "No such command".
    from agent_manifest.cli import TOP_LEVEL_COMMANDS

    assert set(TOP_LEVEL_COMMANDS) <= set(cli.commands)
    for name in TOP_LEVEL_COMMANDS:
        result = CliRunner().invoke(cli, [name, "--help"])
        assert result.exit_code == 0, f"`manifest {name} --help` failed"


def test_deprecated_nested_invocation_still_works(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)
    public_path = _write_public_key(tmp_path, keypair)

    result = CliRunner().invoke(
        cli,
        [
            "manifest", "verify", str(signed_path), "--public-key", str(public_path),
            "--signature-only",
        ],
    )

    assert result.exit_code == 0
    assert _json_stdout(result)["result"] == "VALID"
    assert "deprecated" in result.stderr


def test_deprecated_group_is_hidden_from_help():
    result = CliRunner().invoke(cli, ["--help"])

    assert result.exit_code == 0
    assert "verify" in result.output
    # The alias exists for old scripts but must not be advertised.
    assert "\n  manifest " not in result.output


# ---------------------------------------------------------------------------
# HITL approver keys
#
# Approvals attach outside the manifest signature, so the relying party has to
# supply the approver keys it trusts. Without --approver-key there is no CLI
# input that can populate approver_public_keys, and every approval is
# UNVERIFIABLE regardless of whether it is genuine.
# ---------------------------------------------------------------------------


def _hitl_approval(approver_keypair, *, manifest_id, signature=None):
    approved_at = (
        datetime.now(timezone.utc) - timedelta(minutes=30)
    ).isoformat().replace("+00:00", "Z")
    scope = {"approval_duration_seconds": 7200}
    approval = {
        "approver_id": APPROVER_ID,
        "approved_at": approved_at,
        "approved_scope": scope,
        "approval_method": "hardware-key",
    }
    approval["approval_signature"] = signature or HitlApprovalSigner(
        approver_keypair
    ).sign_approval(
        manifest_id=manifest_id,
        approved_at=approved_at,
        approved_scope=scope,
        approver_id=APPROVER_ID,
        approval_method=approval["approval_method"],
    )
    return approval


def _write_hitl_manifest(tmp_path: Path, keypair, approval) -> Path:
    """Sign a manifest whose hitl_record already carries *approval*.

    Approvals are normalized out of the signing pre-image (spec 3.6), so the
    manifest signature stays valid with the approval attached.
    """
    manifest = _signed_manifest(keypair)
    manifest["hitl_record"] = {"required": True, "approvals": [approval]}
    manifest["signature"] = Ed25519Signer(keypair).sign(manifest)
    signed_path = tmp_path / "hitl.json"
    signed_path.write_text(json.dumps(manifest))
    return signed_path


def _write_approver_key(tmp_path: Path, keypair) -> Path:
    approver_path = tmp_path / "approver.hex"
    approver_path.write_text(keypair.public_bytes.hex())
    return approver_path


def test_cli_verify_hitl_with_trusted_approver_key_is_valid(tmp_path):
    keypair = generate_ed25519()
    approver = generate_ed25519()
    manifest_path = _write_hitl_manifest(
        tmp_path,
        keypair,
        _hitl_approval(approver, manifest_id=_signed_manifest(keypair)["manifest_id"]),
    )

    result = CliRunner().invoke(cli, [
        "verify", str(manifest_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--approver-key", f"{APPROVER_ID}={_write_approver_key(tmp_path, approver)}",
        "--enforce-hitl", "--signature-only",
    ])

    payload = _json_stdout(result)
    assert result.exit_code == 0
    assert payload["result"] == "VALID"
    assert payload["fields_verified"]["hitl_record"] == "APPROVED"


def test_cli_verify_hitl_without_approver_key_is_unverifiable(tmp_path):
    keypair = generate_ed25519()
    approver = generate_ed25519()
    manifest_path = _write_hitl_manifest(
        tmp_path,
        keypair,
        _hitl_approval(approver, manifest_id=_signed_manifest(keypair)["manifest_id"]),
    )

    result = CliRunner().invoke(cli, [
        "verify", str(manifest_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--enforce-hitl", "--signature-only",
    ])

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["result"] == "UNVERIFIABLE"
    assert payload["fields_verified"]["hitl_record"] == "UNVERIFIABLE"
    # The operator is told which input is missing, not just that it failed.
    assert "--approver-key" in result.output


def test_cli_verify_hitl_runs_without_enforce_hitl(tmp_path):
    # hitl_record.required drives the check, so a manifest declaring HITL
    # reaches the approver-key path even when the caller never asked for it.
    keypair = generate_ed25519()
    approver = generate_ed25519()
    manifest_path = _write_hitl_manifest(
        tmp_path,
        keypair,
        _hitl_approval(approver, manifest_id=_signed_manifest(keypair)["manifest_id"]),
    )

    result = CliRunner().invoke(cli, [
        "verify", str(manifest_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--signature-only",
    ])

    assert _json_stdout(result)["result"] == "UNVERIFIABLE"


def test_cli_verify_rejects_forged_approval_signature(tmp_path):
    keypair = generate_ed25519()
    approver = generate_ed25519()
    manifest_path = _write_hitl_manifest(
        tmp_path,
        keypair,
        _hitl_approval(
            approver,
            manifest_id=_signed_manifest(keypair)["manifest_id"],
            signature="c2ln",
        ),
    )

    result = CliRunner().invoke(cli, [
        "verify", str(manifest_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--approver-key", f"{APPROVER_ID}={_write_approver_key(tmp_path, approver)}",
        "--enforce-hitl", "--signature-only",
    ])

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["fields_verified"]["hitl_record"] == "INVALID"


def test_cli_verify_rejects_approval_replayed_from_another_manifest(tmp_path):
    keypair = generate_ed25519()
    approver = generate_ed25519()
    manifest_path = _write_hitl_manifest(
        tmp_path,
        keypair,
        _hitl_approval(
            approver, manifest_id="018f4a3b-2c1d-7e5f-a8b9-ffffffffffff"
        ),
    )

    result = CliRunner().invoke(cli, [
        "verify", str(manifest_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--approver-key", f"{APPROVER_ID}={_write_approver_key(tmp_path, approver)}",
        "--enforce-hitl", "--signature-only",
    ])

    payload = _json_stdout(result)
    assert result.exit_code == 1
    assert payload["fields_verified"]["hitl_record"] == "INVALID"


def test_cli_verify_rejects_malformed_approver_key_spec(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)

    result = CliRunner().invoke(cli, [
        "verify", str(signed_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--approver-key", "no-separator-here",
    ])

    assert result.exit_code != 0
    assert "APPROVER_ID=PATH" in result.output


def test_cli_verify_rejects_missing_approver_key_file(tmp_path):
    keypair = generate_ed25519()
    signed_path = _write_signed_manifest(tmp_path, keypair)

    result = CliRunner().invoke(cli, [
        "verify", str(signed_path),
        "--public-key", str(_write_public_key(tmp_path, keypair)),
        "--approver-key", f"{APPROVER_ID}={tmp_path / 'absent.hex'}",
    ])

    assert result.exit_code != 0
    assert "Approver key file not found" in result.output


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits only")
@pytest.mark.parametrize("umask", [0o022, 0o077, 0o777])
def test_cli_keygen_private_key_mode_0600_under_umask(tmp_path, umask):
    """CRYPTO-008/SEC-005: private.hex must end up 0600 regardless of umask.

    0o777 is the interesting case: os.open()'s mode argument is itself
    narrowed by the umask, so without an explicit fchmod() a maximally
    restrictive umask would leave the file at 0000 -- unreadable even by
    its owner -- instead of the intended 0600.
    """
    old_umask = os.umask(umask)
    try:
        priv_path = tmp_path / "private.hex"
        result = CliRunner().invoke(cli, ["keygen", "-d", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert stat.S_IMODE(os.stat(priv_path).st_mode) == 0o600
    finally:
        os.umask(old_umask)


def test_cli_keygen_refuses_to_overwrite_existing_private_key(tmp_path):
    """keygen must not touch an existing private.hex, not even to fix its mode.

    Overwriting in place is unsafe even with a perfect chmod: if something
    already has the old file open for reading, it keeps reading the same
    inode and would see the brand-new key. Refusing outright avoids that
    case entirely instead of trying to out-race it.

    The file's mode is recorded rather than hardcoded because os.chmod()
    on Windows doesn't implement Unix permission bits -- it only toggles
    the read-only attribute -- so a literal 0o400 check wouldn't hold there.

    The fixture mode is 0o400 (owner read-only) rather than the 0600
    keygen would produce: it's still a different value, so the
    mode-preserved assertion below actually proves something, but unlike
    0o640/0o644 it grants no group or other access, so the fixture is
    never itself group- or world-readable, even transiently.
    """
    priv_path = tmp_path / "private.hex"
    priv_path.write_text("existing-key-material")
    os.chmod(priv_path, 0o400)
    original_mode = stat.S_IMODE(priv_path.stat().st_mode)

    result = CliRunner().invoke(cli, ["keygen", "-d", str(tmp_path)])

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert priv_path.read_text() == "existing-key-material"
    assert stat.S_IMODE(priv_path.stat().st_mode) == original_mode


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_cli_keygen_refuses_symlink_private_key(tmp_path):
    """O_EXCL must refuse to follow a private.hex that's actually a symlink.

    Not required for the confidentiality fix itself (the pre-open-FD test
    below already covers that), but it locks in a property the implementation
    comment explicitly relies on.
    """
    target = tmp_path / "target"
    private = tmp_path / "private.hex"

    target.write_text("do-not-touch")
    private.symlink_to(target)

    result = CliRunner().invoke(cli, ["keygen", "-d", str(tmp_path)])

    assert result.exit_code != 0
    assert target.read_text() == "do-not-touch"
    assert private.is_symlink()


@pytest.mark.skipif(sys.platform == "win32", reason="requires POSIX file descriptors")
def test_cli_keygen_never_leaks_new_key_through_a_preopened_descriptor(tmp_path):
    """End-to-end reproduction of the pre-open-FD disclosure this patch closes.

    Simulates an attacker who opened a loosely-permissioned private.hex
    before keygen ran. Since keygen now refuses to write into an existing
    file at all, that pre-opened descriptor must never see new key
    material -- only whatever was there before.
    """
    priv_path = tmp_path / "private.hex"
    priv_path.write_text("OLD-SECRET-KEY")
    # 0o400 (owner read-only): the "attacker" here is just this same test
    # process holding an earlier file descriptor open, so no group/other
    # bits are needed to exercise that path, and none are granted.
    os.chmod(priv_path, 0o400)

    attacker_fd = os.open(str(priv_path), os.O_RDONLY)
    try:
        result = CliRunner().invoke(cli, ["keygen", "-d", str(tmp_path)])
        assert result.exit_code != 0

        os.lseek(attacker_fd, 0, os.SEEK_SET)
        data = os.read(attacker_fd, 4096)
        assert data == b"OLD-SECRET-KEY"
    finally:
        os.close(attacker_fd)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits only")
def test_cli_keygen_private_key_created_with_mode_0600_and_o_excl(tmp_path, monkeypatch):
    """CRYPTO-008/SEC-005 regression test (deterministic, not timing-based).

    The private key file must be created with O_EXCL and mode 0600 passed
    directly to the creating syscall -- both so the mode is never applied
    after the fact (the original write-then-chmod TOCTOU) and so an
    existing file is never truncated and reused (the FD-disclosure case).
    """
    calls = []
    real_open = os.open

    def spying_open(path, flags, *args, **kwargs):
        if os.fspath(path).endswith("private.hex") and (flags & os.O_CREAT):
            mode = args[0] if args else kwargs.get("mode")
            calls.append((flags, mode))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spying_open)

    result = CliRunner().invoke(cli, ["keygen", "-d", str(tmp_path)])
    assert result.exit_code == 0, result.output

    assert len(calls) == 1
    flags, mode = calls[0]
    assert mode == 0o600
    assert flags & os.O_EXCL
    assert not flags & os.O_TRUNC
