#!/usr/bin/env bash
# Demonstrates revocation lifecycle using the Python SDK.
# Run from the repo root: bash examples/revocation/demo.sh
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "=== Revocation Example ==="
echo

python3 - <<'PYEOF'
import json
from pathlib import Path

BASE = Path("examples/revocation")

manifest  = json.loads((BASE / "valid-manifest.json").read_text())
crl_lines = (BASE / "crl.jsonl").read_text().strip().splitlines()

manifest_id = manifest["manifest_id"]

# ── 1. Pre-revocation: manifest is in-scope (not in CRL) ─────────────────────
from agent_manifest._verify import verify_manifest, VerificationContext, RevocationStore, OverallResult

empty_store = RevocationStore()
result = verify_manifest(manifest, VerificationContext(), empty_store)

print(f"Step 1 — Before revocation:")
print(f"  manifest_id: {manifest_id}")
print(f"  result:      {result.result.value}")
# Note: signature placeholder won't verify — we're demonstrating the revocation
# check only. In production, the signature would be real.
print()

# ── 2. Load the CRL and mark the manifest revoked ─────────────────────────────
from agent_manifest._verify import RevocationRecord
from datetime import datetime, timezone

revocation_store = RevocationStore()
for line in crl_lines:
    rec = json.loads(line)
    revocation_store.revoke(RevocationRecord(
        manifest_id=rec["manifest_id"],
        revoked_at=datetime.fromisoformat(rec["revoked_at"].replace("Z", "+00:00")),
        reason=rec["reason"],
        revoked_by=rec["revoked_by"],
    ))

print(f"Step 2 — CRL loaded ({len(crl_lines)} record(s)):")
print(f"  {manifest_id} in CRL: {revocation_store.is_revoked(manifest_id)}")
print()

# ── 3. Post-revocation: manifest is rejected ──────────────────────────────────
result = verify_manifest(manifest, VerificationContext(), revocation_store)
print(f"Step 3 — After revocation:")
print(f"  result:      {result.result.value}")

assert result.result == OverallResult.REVOKED, f"Expected REVOKED, got {result.result}"
print()
print("Demo complete. Manifest rejected with REVOKED as expected.")
PYEOF
