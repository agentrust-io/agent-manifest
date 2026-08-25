"""CLI round-trip for version 0.2 COSE manifests.

The command surface must not grow a flag for this: the envelope follows the
manifest version on the way out and the CBOR tag on the way in, so a user
signs and verifies the same way regardless of which envelope applies.
"""
import json
from datetime import datetime, timedelta, timezone

import cbor2
import pytest
from click.testing import CliRunner

from agent_manifest._signing import ed25519_from_private_bytes
from agent_manifest.cli import cli

SEED = bytes(range(32))
KP = ed25519_from_private_bytes(SEED)
NOW = datetime.now(timezone.utc)
FUTURE = (NOW + timedelta(days=90)).isoformat().replace("+00:00", "Z")
SHA = "sha256:" + "a" * 64


def manifest(version="0.2", **overrides):
    m = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/agent/kyc/prod",
        "version": version,
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": FUTURE,
        "issuer": "spiffe://trust.example/signing-authority",
        "crypto_profile": "standard",
        "artifacts": {"system_prompt": {"hash": SHA}},
    }
    m.update(overrides)
    return m


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "key.hex").write_text(SEED.hex())
    (tmp_path / "pub.hex").write_text(KP.public_bytes.hex())
    return tmp_path


def run(*args):
    return CliRunner().invoke(cli, [str(a) for a in args])


def test_signing_a_v02_manifest_produces_a_cose_envelope(workspace):
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest()))
    signed = workspace / "signed.cose"

    result = run("sign", draft, "--key", workspace / "key.hex", "-o", signed)
    assert result.exit_code == 0, result.output
    assert "COSE_Sign1" in result.output

    tagged = cbor2.loads(signed.read_bytes())
    assert tagged.tag == 18
    assert json.loads(tagged.value[2].decode())["manifest_id"] == (
        manifest()["manifest_id"]
    )


def test_signing_a_v01_manifest_is_unchanged(workspace):
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest(version="0.1")))
    signed = workspace / "signed.json"

    result = run("sign", draft, "--key", workspace / "key.hex", "-o", signed)
    assert result.exit_code == 0, result.output
    data = json.loads(signed.read_text())
    assert data["signature"]["algorithm"] == "Ed25519"


def test_a_cose_envelope_is_not_written_to_the_terminal(workspace):
    """Binary CBOR down stdout would corrupt it; refuse instead."""
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest()))
    result = run("sign", draft, "--key", workspace / "key.hex")
    assert result.exit_code != 0
    assert "--output" in result.output


def test_verify_detects_the_envelope_from_the_cbor_tag(workspace):
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest()))
    signed = workspace / "signed.cose"
    run("sign", draft, "--key", workspace / "key.hex", "-o", signed)

    out = workspace / "result.json"
    result = run(
        "verify", signed, "--public-key", workspace / "pub.hex", "--signature-only", "-o", out
    )
    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text())["result"] == "VALID"


def test_verify_reports_a_tampered_envelope(workspace):
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest()))
    signed = workspace / "signed.cose"
    run("sign", draft, "--key", workspace / "key.hex", "-o", signed)

    corrupted = bytearray(signed.read_bytes())
    corrupted[-1] ^= 0x01
    signed.write_bytes(bytes(corrupted))

    out = workspace / "result.json"
    result = run(
        "verify", signed, "--public-key", workspace / "pub.hex", "-o", out
    )
    assert result.exit_code == 1
    assert json.loads(out.read_text())["result"] == "MISMATCH"


def test_verify_without_a_key_is_unverifiable_never_valid(workspace):
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest()))
    signed = workspace / "signed.cose"
    run("sign", draft, "--key", workspace / "key.hex", "-o", signed)

    out = workspace / "result.json"
    result = run("verify", signed, "-o", out)
    assert result.exit_code == 1
    assert json.loads(out.read_text())["result"] == "UNVERIFIABLE"


def test_a_file_that_is_neither_json_nor_cose_is_refused(workspace):
    junk = workspace / "junk.bin"
    junk.write_bytes(b"\x00\x01\x02 not a manifest")
    result = run("verify", junk)
    assert result.exit_code != 0
    assert "neither JSON nor a COSE envelope" in result.output


def test_the_round_trip_is_reproducible(workspace):
    """Ed25519 is deterministic, so signing twice gives identical bytes."""
    draft = workspace / "draft.json"
    draft.write_text(json.dumps(manifest()))
    first, second = workspace / "a.cose", workspace / "b.cose"
    run("sign", draft, "--key", workspace / "key.hex", "-o", first)
    run("sign", draft, "--key", workspace / "key.hex", "-o", second)
    assert first.read_bytes() == second.read_bytes()
