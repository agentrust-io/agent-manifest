"""Collect executable reference-suite node IDs; check the committed inventory."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULES = ("bind", "crypto", "attest", "verify", "compat")
INVENTORY = ROOT / "docs" / "conformance-inventory.json"


def collect() -> dict[str, object]:
    env = dict(os.environ)
    env.pop("PYTEST_ADDOPTS", None)
    env["PYTHONPATH"] = str(ROOT / "python" / "src")
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="]
    command.extend(f"tests/test_am_{name}.py" for name in MODULES)
    result = subprocess.run(
        command,
        cwd=ROOT / "python",
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    nodes = sorted(
        line
        for line in result.stdout.splitlines()
        if re.fullmatch(
            r"tests/test_am_(bind|crypto|attest|verify|compat)\.py::.+", line
        )
    )
    if not nodes or len(nodes) != len(set(nodes)):
        raise RuntimeError("collection produced no nodes or duplicate node IDs")
    modules = {}
    for name in MODULES:
        path = f"tests/test_am_{name}.py"
        selected = [node for node in nodes if node.startswith(path + "::")]
        if not selected:
            raise RuntimeError(f"no cases collected for {path}")
        modules[f"AM-{name.upper()}"] = {
            "path": path,
            "count": len(selected),
            "node_ids": selected,
        }
    return {"format_version": 1, "total_collected": len(nodes), "modules": modules}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="regenerate the committed inventory"
    )
    args = parser.parse_args()
    actual = collect()
    serialized = json.dumps(actual, indent=2, ensure_ascii=False) + "\n"
    if args.write:
        INVENTORY.write_text(serialized, encoding="utf-8")
    elif not INVENTORY.exists() or INVENTORY.read_text(encoding="utf-8") != serialized:
        print(
            "Conformance inventory changed; run scripts/conformance_inventory.py --write, "
            "then reconcile the documented counts and review the diff.",
            file=sys.stderr,
        )
        return 1
    for filename in ("spec/agent-manifest-spec-v0.2.md", "docs/spec-overview.md"):
        text = (ROOT / filename).read_text(encoding="utf-8")
        for module, details in actual["modules"].items():
            match = re.search(
                r"^\| " + module + r" \| (\d+)(?: tests)? \|", text, re.MULTILINE
            )
            if match is None or int(match[1]) != details["count"]:
                print(
                    f"{filename}: {module} count differs from collection",
                    file=sys.stderr,
                )
                return 1
    total = actual["total_collected"]
    summaries = {
        "README.md": f"_{total}_tests-",
        "ROADMAP.md": f"{total}-test",
        "docs/spec-overview.md": f"| **Total** | **{total}** |",
        "spec/agent-manifest-spec-v0.2.md": f"Total: {total} collected reference test cases",
    }
    for filename, expected in summaries.items():
        if expected not in (ROOT / filename).read_text(encoding="utf-8"):
            print(f"{filename}: total differs from collection", file=sys.stderr)
            return 1
    print(f"{actual['total_collected']} collected cases; inventory matches collection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
