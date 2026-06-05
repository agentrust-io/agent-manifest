#!/usr/bin/env bash
# Demonstrates multi-artifact integrity checking using the Python SDK.
# Run from the repo root: bash examples/multi-artifact/verify.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "=== Multi-Artifact Manifest Example ==="
echo

python3 - <<'PYEOF'
import hashlib
import json
from pathlib import Path
from copy import deepcopy

BASE = Path("examples/multi-artifact")
manifest = json.loads((BASE / "manifest.json").read_text())

# ── 1. Compute runtime hashes from the actual artifact files ──────────────────

def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

runtime_system_prompt  = sha256_file(BASE / "artifacts" / "system-prompt.txt")
runtime_tool_catalog   = sha256_file(BASE / "artifacts" / "tool-catalog.json")
runtime_rag_root       = sha256_file(BASE / "artifacts" / "rag-corpus-root.txt")

print("Step 1 — Runtime artifact hashes:")
print(f"  system_prompt:  {runtime_system_prompt}")
print(f"  tool_catalog:   {runtime_tool_catalog}")
print(f"  rag_corpus:     {runtime_rag_root}")
print()

# ── 2. Compare against manifest bindings ─────────────────────────────────────
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore, OverallResult, FieldResult

ctx = VerificationContext(
    system_prompt_hash=runtime_system_prompt,
    tool_catalog_hash=runtime_tool_catalog,
    rag_corpus_merkle_root=runtime_rag_root,
)
store = RevocationStore()
result = verify_manifest(manifest, ctx, store)

print("Step 2 — Verification against manifest bindings:")
fv = result.fields_verified
print(f"  system_prompt: {fv.system_prompt.value}")
print(f"  tool_manifest: {fv.tool_manifest.value}")
print(f"  rag_corpus:    {fv.rag_corpus.value}")
print()

# ── 3. Tamper the system prompt and re-verify ─────────────────────────────────
tampered_hash = "sha256:" + hashlib.sha256(b"TAMPERED CONTENT").hexdigest()
ctx_tampered = VerificationContext(
    system_prompt_hash=tampered_hash,
    tool_catalog_hash=runtime_tool_catalog,
    rag_corpus_merkle_root=runtime_rag_root,
)
result_tampered = verify_manifest(manifest, ctx_tampered, store)

print("Step 3 — Tampered system prompt:")
fv2 = result_tampered.fields_verified
print(f"  system_prompt: {fv2.system_prompt.value}")
print(f"  overall result: {result_tampered.result.value}")
if result_tampered.mismatch_details:
    m = result_tampered.mismatch_details[0]
    print(f"  expected: {m.expected_hash}")
    print(f"  actual:   {m.actual_hash}")
print()

assert fv2.system_prompt == FieldResult.MISMATCH, "Expected MISMATCH on tampered prompt"
print("Tamper detection: PASSED")
print("Demo complete.")
PYEOF
