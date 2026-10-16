"""Probe: does verify_manifest authenticate HITL approvals?

Sign the committed HITL example, then replace every approval's approver and
approval_signature with forged values, and re-verify WITHOUT re-signing.
The SDK clock is frozen at the original run time (see run_frozen_clock.py).
"""
import copy, datetime as _dt, json, os, sys
from pathlib import Path

ROOT = Path(os.environ["AGENT_MANIFEST_ROOT"])
sys.path.insert(0, str(ROOT / "python" / "src"))
FROZEN = _dt.datetime(2026, 7, 1, 20, 45, 42, tzinfo=_dt.timezone.utc)
class F(_dt.datetime):
    @classmethod
    def now(cls, tz=None): return FROZEN if tz else FROZEN.replace(tzinfo=None)

from agent_manifest._signing import generate_ed25519, Ed25519Signer
from agent_manifest import _verify
from agent_manifest._verify import RevocationStore, VerificationContext, verify_manifest
for n, m in list(sys.modules.items()):
    if n.startswith("agent_manifest") and getattr(m, "datetime", None) is _dt.datetime:
        m.datetime = F

m = json.loads((ROOT / "examples" / "hitl" / "manifest-with-hitl.json").read_text(encoding="utf-8"))
m.pop("signature", None)
kp = generate_ed25519()
m["signature"] = Ed25519Signer(kp).sign(m)
out = {}
for enforce in (False, True):
    ctx = VerificationContext(trusted_keys={kp.key_id: kp.public_b64url()}, enforce_hitl=enforce)
    base = verify_manifest(m, ctx, RevocationStore())
    forged = copy.deepcopy(m)
    for a in forged["hitl_record"]["approvals"]:
        for k in ("approver_id", "approver", "approver_identity"):
            if k in a: a[k] = "mailto:forged-approver@attacker.example"
        a["approval_signature"] = "AAAA"
    r = verify_manifest(forged, ctx, RevocationStore())
    out[f"enforce_hitl={enforce}"] = {
        "original": [base.result.value, base.fields_verified.hitl_record.value],
        "forged_approvals": [r.result.value, r.fields_verified.hitl_record.value, r.signature_verified],
    }
print(json.dumps(out, indent=2))
print("approval keys:", sorted(m["hitl_record"]["approvals"][0].keys()))
