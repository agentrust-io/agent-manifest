#!/usr/bin/env bash
# Demonstrates delegation chain verification using the Python SDK.
# Run from the repo root: bash examples/delegation-chain/verify.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "=== A2A Delegation Chain Example ==="
echo

python3 - <<'PYEOF'
import json
from pathlib import Path

BASE = Path("examples/delegation-chain")

# Load the three manifests
root     = json.loads((BASE / "root-manifest.json").read_text())
delegate = json.loads((BASE / "delegate-manifest.json").read_text())
sub      = json.loads((BASE / "sub-delegate-manifest.json").read_text())

# ── 1. Show the delegation chain depth at each level ──────────────────────────
print(f"Orchestrator  ({root['agent_id']!r})")
print(f"  delegation_chain length: {len(root['delegation_chain'])} (root — no delegation)")
print()
print(f"Executor      ({delegate['agent_id']!r})")
print(f"  delegation_chain length: {len(delegate['delegation_chain'])} (one hop from orchestrator)")
print(f"  hop 0 scope: {delegate['delegation_chain'][0]['scope_grant']['tools']}")
print()
print(f"Data-fetcher  ({sub['agent_id']!r})")
print(f"  delegation_chain length: {len(sub['delegation_chain'])} (two hops)")
print(f"  hop 0 scope: {sub['delegation_chain'][0]['scope_grant']['tools']}")
print(f"  hop 1 scope: {sub['delegation_chain'][1]['scope_grant']['tools']}")
print()

# ── 2. Verify scope narrowing ─────────────────────────────────────────────────
hop0_tools = set(sub['delegation_chain'][0]['scope_grant']['tools'])
hop1_tools = set(sub['delegation_chain'][1]['scope_grant']['tools'])
assert hop1_tools.issubset(hop0_tools), "Scope laundering: hop 1 claims tools not in hop 0!"
print("Scope narrowing check: PASSED")
print(f"  hop 0 grants: {sorted(hop0_tools)}")
print(f"  hop 1 grants: {sorted(hop1_tools)}")
print(f"  hop 1 is a strict subset: {hop1_tools < hop0_tools}")
print()

# ── 3. Show what scope laundering looks like ──────────────────────────────────
print("Scope laundering detection:")
tampered_scope = {"tools": ["fetch_public_data", "run_analysis", "EXTRA_TOOL"]}
parent_tools   = set(hop0_tools)
child_tools    = set(tampered_scope["tools"])
if not child_tools.issubset(parent_tools):
    extra = child_tools - parent_tools
    print(f"  BLOCKED: child claims {extra} not granted by parent")
print()

print("All checks passed.")
PYEOF
