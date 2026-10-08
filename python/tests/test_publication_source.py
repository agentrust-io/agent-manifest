"""Release workflow guard regression tests; no workflow is dispatched."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish.yml"


@unittest.skipUnless(shutil.which("bash"), "publisher guard requires bash")
class TestPublicationSource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.block = workflow.split(
            "      - name: Verify publication source\n", 1
        )[1].split("      - name:", 1)[0]
        cls.script = textwrap.dedent(cls.block.split("        run: |\n", 1)[1])

    def run_guard(self, event, ref, mode=""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "python").mkdir()
            (root / "python/pyproject.toml").write_text(
                '[project]\nversion = "1.2.3"\n', encoding="utf-8"
            )
            result = subprocess.run(
                ["bash", "-c", self.script], cwd=root,
                env=dict(os.environ, EVENT_NAME=event, GITHUB_REF=ref,
                         RELEASE_MODE=mode),
                capture_output=True, text=True, timeout=10,
            )
        return result

    def test_valid_tagged_publication_and_build_only_paths(self):
        cases = [
            ("push", "refs/tags/python-v1.2.3", ""),
            ("workflow_dispatch", "refs/tags/python-v1.2.3", "publish"),
            ("workflow_dispatch", "refs/heads/main", "build-only"),
            ("workflow_dispatch", "refs/tags/python-v9.9.9", "build-only"),
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.run_guard(*case)
                self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_unmatched_or_implicit_publication_fails(self):
        cases = [
            ("push", "refs/tags/python-v9.9.9", ""),
            ("push", "refs/heads/main", ""),
            ("workflow_dispatch", "refs/heads/main", "publish"),
            ("workflow_dispatch", "refs/tags/python-v9.9.9", "publish"),
            ("workflow_dispatch", "refs/tags/v1.2.3", "publish"),
            ("workflow_dispatch", "refs/tags/python-v1.2.3", ""),
            ("workflow_dispatch", "refs/tags/python-v1.2.3", "invalid"),
            ("release", "refs/tags/python-v1.2.3", "publish"),
        ]
        for case in cases:
            with self.subTest(case=case):
                result = self.run_guard(*case)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("::error::", result.stdout)

    def test_guard_runs_unconditionally_before_build(self):
        self.assertNotRegex(self.block, re.compile(r"^\s+if:", re.MULTILINE))
        self.assertNotRegex(
            self.block, re.compile(r"^\s+continue-on-error:", re.MULTILINE)
        )
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(
            workflow.index("      - name: Verify publication source"),
            workflow.index("      - name: Build wheel and sdist"),
        )

    def test_publication_job_excludes_build_only_dispatch(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        publish = workflow.split("\n  publish:\n", 1)[1].split(
            "\n  github-release:\n", 1
        )[0]
        self.assertIn("startsWith(github.ref, 'refs/tags/python-v')", publish)
        self.assertIn("inputs.mode == 'publish'", publish)
        self.assertIn("github.event_name == 'push'", publish)
        self.assertIn("    needs: [validate, build]", publish)
        self.assertIn("needs.validate.result == 'success'", publish)
        self.assertIn("needs.build.result == 'success'", publish)
        self.assertIn("        default: build-only\n", workflow)
        self.assertIn("    needs: publish\n", workflow)


def _job(workflow, name):
    return re.split(r"\n  \S", workflow.split(f"\n  {name}:\n", 1)[1], maxsplit=1)[0]


def _condition(block):
    lines = block.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("    if: "):
            value = line.removeprefix("    if: ")
            if value == ">-":
                continued = []
                for following in lines[i + 1:]:
                    if not following.startswith("      "):
                        break
                    continued.append(following.strip())
                value = " ".join(continued)
            return value
    raise AssertionError("missing release gate")


def _eligible(expression, **values):
    import ast

    for token, value in values.items():
        expression = expression.replace(token, repr(value))
    expression = expression.replace("&&", " and ").replace("||", " or ")
    tree = ast.parse(expression, mode="eval")
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq,
               ast.Constant, ast.Load, ast.Call, ast.Name)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            raise AssertionError(f"unexpected release expression: {expression}")
        if isinstance(node, ast.Name) and node.id != "startsWith":
            raise AssertionError(f"unexpected function: {node.id}")
    return eval(compile(tree, "<release gate>", "eval"),
                {"__builtins__": {}, "startsWith": lambda value, prefix: value.startswith(prefix)})


class TestReleaseValidation(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text()
        self.build = _job(self.workflow, "build")
        self.publish = _job(self.workflow, "publish")

    def test_same_revision_full_ci_blocks_build_and_publish(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("  workflow_call:\n", ci)
        self.assertIn("uses: ./.github/workflows/ci.yml", _job(self.workflow, "validate"))
        self.assertIn("    needs: validate\n", self.build)
        self.assertIn("    needs: [validate, build]\n", self.publish)
        self.assertNotRegex(self.workflow, r"(?m)^\s+ref:")
        self.assertNotIn("continue-on-error:", self.workflow)
        for status in ("success", "failure", "cancelled", "skipped"):
            values = {"success()": True, "needs.validate.result": status,
                      "needs.build.result": "success", "github.event_name": "push",
                      "github.ref": "refs/tags/python-v1.2.3", "inputs.mode": ""}
            self.assertEqual(_eligible(_condition(self.build), **values), status == "success")
            self.assertEqual(_eligible(_condition(self.publish), **values), status == "success")

    def test_artifact_failures_and_cancellation_block_publication(self):
        for status in ("failure", "cancelled", "skipped"):
            self.assertFalse(_eligible(_condition(self.publish), **{
                "success()": True, "needs.validate.result": "success",
                "needs.build.result": status, "github.event_name": "push",
                "github.ref": "refs/tags/python-v1.2.3", "inputs.mode": ""}))
        self.assertFalse(_eligible(_condition(self.publish), **{
            "success()": False, "needs.validate.result": "success",
            "needs.build.result": "success", "github.event_name": "push",
            "github.ref": "refs/tags/python-v1.2.3", "inputs.mode": ""}))

    def test_only_tagged_explicit_publication_is_eligible(self):
        for event, ref, mode, expected in (
            ("push", "refs/tags/python-v1.2.3", "", True),
            ("workflow_dispatch", "refs/tags/python-v1.2.3", "publish", True),
            ("workflow_dispatch", "refs/tags/python-v1.2.3", "build-only", False),
            ("workflow_dispatch", "refs/tags/python-v1.2.3", "", False),
            ("workflow_dispatch", "refs/heads/main", "publish", False),
            ("push", "refs/heads/main", "", False),
            ("release", "refs/tags/python-v1.2.3", "publish", False),
        ):
            with self.subTest(event=event, ref=ref, mode=mode):
                self.assertEqual(_eligible(_condition(self.publish), **{
                    "success()": True, "needs.validate.result": "success",
                    "needs.build.result": "success", "github.event_name": event,
                    "github.ref": ref, "inputs.mode": mode}), expected)

    def test_only_publishing_job_has_pypi_authority_and_release_waits_for_it(self):
        self.assertNotIn("environment:", self.build)
        self.assertNotIn("id-token:", self.build)
        self.assertIn("    environment: pypi\n", self.publish)
        self.assertIn("      id-token: write\n", self.publish)
        self.assertIn("    needs: publish\n", _job(self.workflow, "github-release"))
        self.assertIn("Install and smoke-test wheel and sdist", self.build)
        self.assertIn("verify_python_distribution.py", self.build)


if __name__ == "__main__":
    unittest.main()
