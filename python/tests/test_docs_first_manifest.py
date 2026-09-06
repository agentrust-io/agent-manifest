"""Execute the complete onboarding example and inspect its saved artifact."""
import json
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
