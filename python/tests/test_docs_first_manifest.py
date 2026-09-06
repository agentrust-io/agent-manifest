"""Execute the complete onboarding example and inspect its saved artifact."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_manifest.cli import cli


def test_first_manifest(tmp_path):
    page = Path(__file__).resolve().parents[2] / "docs/getting-started.md"
    if not page.is_file():
        pytest.skip("documentation is not included in the sdist")
    blocks = re.findall(r"^```python\n(.*?)^```", page.read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL)
    assert len(blocks) == 1
    run = subprocess.run(
        [sys.executable, "-c", blocks[0]], cwd=tmp_path, capture_output=True, text=True, check=False
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.count("PASS:") == 3
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", str(tmp_path / "signed.json"),
                                 "--public-key", str(tmp_path / "public.hex")])
    payload = json.loads(result.stdout)
    assert payload["result"] == "INCOMPLETE"
    assert payload["signature_verified"] is True
    result = runner.invoke(cli, ["verify", str(tmp_path / "signed.json")])
    assert json.loads(result.stdout)["result"] == "UNVERIFIABLE"


@pytest.mark.parametrize("relative, expected", [
    ("tutorials/revocation-and-key-rotation.md", (
        "PASS: refreshed revocation state rejects the manifest",
        "PASS: untrusted revocation signer rejected",
    )),
    ("integrations/index.md", (
        "PASS: approved manifest accepted by the gate",
        "PASS: missing trust and changed runtime input blocked",
    )),
    ("tutorials/hitl-approval-workflows.md", (
        "PASS: missing required approval rejected",
        "PASS: trusted software approval accepted",
        "PASS: relabeled approval rejected independently of issuer signature",
    )),
    ("tutorials/server-side-verification.md", (
        "PASS: known manifest accepted; missing and unknown IDs rejected",
        "PASS: changed runtime input rejected before the handler",
        "PASS: diagnostic GET without trusted keys cannot return VALID",
    )),
    ("tutorials/hardware-attestation.md", (
        "PASS: software binding matches the record and rejects an edited record",
        "PASS: a new nonce changes the software binding; no hardware proof was produced",
    )),
])
def test_followup_tutorial(tmp_path, relative, expected):
    docs = Path(__file__).resolve().parents[2] / "docs"
    first = docs / "getting-started.md"
    revocation = docs / relative
    if not first.is_file() or not revocation.is_file():
        pytest.skip("documentation is not included in the sdist")
    blocks = []
    for page in (first, revocation):
        extracted = re.findall(
            r"^```python\n(.*?)^```", page.read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL
        )
        assert len(extracted) == 1
        blocks.extend(extracted)
    run = subprocess.run(
        [sys.executable, "-c", "\n".join(blocks)], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    for message in expected:
        assert message in run.stdout


def test_delegation_tutorial(tmp_path):
    page = Path(__file__).resolve().parents[2] / "docs/tutorials/delegation-chains.md"
    if not page.is_file():
        pytest.skip("documentation is not included in the sdist")
    blocks = re.findall(
        r"^```python\n(.*?)^```", page.read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    assert len(blocks) == 1
    run = subprocess.run(
        [sys.executable, "-c", blocks[0]], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    for message in (
        "PASS: two signed hops with narrowed scope",
        "PASS: signed scope escalation rejected",
        "PASS: replay under another manifest ID rejected",
    ):
        assert message in run.stdout


def test_ci_signing_scripts(tmp_path):
    docs = Path(__file__).resolve().parents[2] / "docs"
    if not (docs / "getting-started.md").is_file():
        pytest.skip("documentation is not included in the sdist")
    first = re.findall(
        r"^```python\n(.*?)^```", (docs / "getting-started.md").read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )[0]
    # Generate local demo inputs; the scripts receive a separately provisioned key.
    setup = first + '\nPath("approved-context.json").write_text(context.model_dump_json())\n'
    run = subprocess.run(
        [sys.executable, "-c", setup], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    scripts = re.findall(
        r"^```python\n(.*?)^```",
        (docs / "tutorials/ci-cd-signing.md").read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    assert len(scripts) == 2
    from agent_manifest import generate_ed25519

    key = generate_ed25519()
    env = dict(os.environ, MANIFEST_SIGNING_KEY=key.private_b64url(),
               MANIFEST_PUBLIC_KEY=key.public_b64url(), MANIFEST_KEY_ID=key.key_id,
               MANIFEST_CONTEXT_FILE="approved-context.json")
    for name, code in zip(("sign.py", "verify.py"), scripts, strict=True):
        (tmp_path / name).write_text(code, encoding="utf-8")
    signed = subprocess.run(
        [sys.executable, "sign.py", "signed.json", "ci-signed.json"], cwd=tmp_path,
        env=env, capture_output=True, text=True, check=False,
    )
    assert signed.returncode == 0, signed.stdout + signed.stderr
    verified = subprocess.run(
        [sys.executable, "verify.py", "ci-signed.json"], cwd=tmp_path,
        env=env, capture_output=True, text=True, check=False,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    assert "OK:" in verified.stdout
    context_file = tmp_path / "approved-context.json"
    context = json.loads(context_file.read_text())
    context["system_prompt_hash"] = "sha256:" + "0" * 64
    context_file.write_text(json.dumps(context))
    rejected = subprocess.run(
        [sys.executable, "verify.py", "ci-signed.json"], cwd=tmp_path,
        env=env, capture_output=True, text=True, check=False,
    )
    assert rejected.returncode == 1, rejected.stdout + rejected.stderr
    assert "MISMATCH" in rejected.stderr
    assert "Traceback" not in rejected.stderr


def test_deployment_service(tmp_path):
    docs = Path(__file__).resolve().parents[2] / "docs"
    if not (docs / "getting-started.md").is_file():
        pytest.skip("documentation is not included in the sdist")
    first = re.findall(
        r"^```python\n(.*?)^```", (docs / "getting-started.md").read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )[0]
    blocks = re.findall(
        r"^```python\n(.*?)^```",
        (docs / "tutorials/deploying-the-verification-endpoint.md").read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    assert len(blocks) == 2
    # Exercise the exact file preparation and app factory in the same demo context.
    checks = '''
from fastapi.testclient import TestClient
from cryptography.exceptions import InvalidSignature

with TestClient(create_app()) as client:
    assert client.get("/ready").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/verify", params={"manifest_id": record["manifest_id"]}).json()["result"] == "VALID"
    assert client.get("/verify", params={"manifest_id": "unknown"}).status_code == 404
    revoked = sign_revocation(manifest_id=record["manifest_id"], reason="demo", revoked_by="demo", keypair=revoker)
    (data / "revocations.jsonl").write_text(revoked.model_dump_json() + "\\n")
    assert client.get("/verify", params={"manifest_id": record["manifest_id"]}).json()["result"] == "VALID"
with TestClient(create_app()) as refreshed:
    assert refreshed.get("/verify", params={"manifest_id": record["manifest_id"]}).json()["result"] == "REVOKED"
for bad_line in ("not JSON", revoked.model_copy(update={"reason": "forged"}).model_dump_json()):
    (data / "revocations.jsonl").write_text(bad_line + "\\n")
    try:
        create_app()
    except (ValueError, InvalidSignature):
        pass
    else:
        raise AssertionError("Invalid revocation file did not fail startup")
(data / "context.json").unlink()
try:
    create_app()
except FileNotFoundError:
    pass
else:
    raise AssertionError("Missing approved context did not fail startup")
print("PASS: deployment readiness, verdicts, refresh, and invalid-input rejection")
'''
    run = subprocess.run(
        [sys.executable, "-c", "\n".join([first, *blocks, checks])], cwd=tmp_path,
        capture_output=True, text=True, check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "PASS: deployment readiness, verdicts, refresh, and invalid-input rejection" in run.stdout
