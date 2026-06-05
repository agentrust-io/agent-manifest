#!/usr/bin/env bash
# Demonstrates HITL verification using the Python SDK.
# Run from the repo root: bash examples/hitl/verify.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "=== HITL Approval Example ==="
echo

python3 - <<'PYEOF'
import json
from copy import deepcopy
from pathlib import Path

BASE = Path("examples/hitl")
manifest = json.loads((BASE / "manifest-with-hitl.json").read_text())

from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore, OverallResult, HitlResult

store = RevocationStore()

# ── 1. Verify with HITL not enforced (default) ────────────────────────────────
ctx = VerificationContext(enforce_hitl=False)
result = verify_manifest(manifest, ctx, store)
print(f"Step 1 — enforce_hitl=False:")
print(f"  result:     {result.result.value}")
print(f"  hitl:       {result.fields_verified.hitl_record.value}")
print()

# ── 2. Verify with HITL enforced — approval is present ────────────────────────
ctx_hitl = VerificationContext(enforce_hitl=True)
result = verify_manifest(manifest, ctx_hitl, store)
print(f"Step 2 — enforce_hitl=True, approval present:")
print(f"  result:     {result.result.value}")
print(f"  hitl:       {result.fields_verified.hitl_record.value}")
print()

# ── 3. Verify without HITL record — should fail with HITL missing ─────────────
no_hitl = deepcopy(manifest)
del no_hitl["hitl_record"]
result = verify_manifest(no_hitl, ctx_hitl, store)
print(f"Step 3 — enforce_hitl=True, approval removed:")
print(f"  result:     {result.result.value}")
print(f"  hitl:       {result.fields_verified.hitl_record.value}")
print()

print("Demo complete.")
PYEOF
