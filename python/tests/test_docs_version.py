"""Regression guard: version strings in docs/index.md must match the installed package."""

import re
import pytest
from importlib.metadata import version
from pathlib import Path

_VERSION_CHECKS = [
    ("TL;DR badge", r"\(https://pypi\.org/project/agent-manifest/\) ([\d]+\.[\d]+\.[\d]+(?:[a-zA-Z]+[\d]+)?)"),
    ("Status footer", r"\*\*Status:\*\* SDK ([\d]+\.[\d]+\.[\d]+(?:[a-zA-Z]+[\d]+)?)"),
]


def test_docs_index_version_matches_installed_package() -> None:
    docs_index = Path(__file__).parents[2] / "docs" / "index.md"
    if not docs_index.exists():
        pytest.skip("docs/index.md not present in this checkout")

    content = docs_index.read_text(encoding="utf-8")
    expected = version("agent-manifest")

    for label, pattern in _VERSION_CHECKS:
        matches = re.findall(pattern, content)
        assert len(matches) == 1, (
            f"Expected exactly one version in '{label}', found {matches}. "
            "Update docs/index.md to match."
        )
        assert matches[0] == expected, (
            f"'{label}' has version {matches[0]!r}, "
            f"but installed package is {expected!r}. "
            "Update docs/index.md to match."
        )
