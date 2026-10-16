"""Run bench.py with the SDK's clock frozen at the original run time.

The committed example manifests expire on 2026-09-02 and 2026-09-10, so after
those dates bench.py's VALID sanity assertion fails with EXPIRED. This wrapper
replaces `datetime` inside every loaded agent_manifest module with a subclass
whose now() returns the original run's timestamp (bench.json env.timestamp,
2026-07-01T20:45:42Z). Nothing else changes.
"""
import datetime as _dt
import os
import sys
from pathlib import Path

FROZEN = _dt.datetime(2026, 7, 1, 20, 45, 42, tzinfo=_dt.timezone.utc)


class FrozenDatetime(_dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN if tz is not None else FROZEN.replace(tzinfo=None)

    @classmethod
    def utcnow(cls):
        return FROZEN.replace(tzinfo=None)


sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench  # noqa: E402  (imports the SDK from AGENT_MANIFEST_ROOT)

patched = []
for name, mod in list(sys.modules.items()):
    if name.startswith("agent_manifest") and getattr(mod, "datetime", None) is _dt.datetime:
        mod.datetime = FrozenDatetime
        patched.append(name)
bench.datetime = FrozenDatetime
print("frozen clock:", FROZEN.isoformat(), "patched:", sorted(patched))
bench.main()
