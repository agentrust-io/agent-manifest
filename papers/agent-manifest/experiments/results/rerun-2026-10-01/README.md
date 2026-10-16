# Agent Manifest rerun, 2026-10-01

Independent rerun of `experiments/bench.py` for technical report version 1.
The committed `results/bench.json` is not modified.

## Revision

The original run (2026-07-01T20:45:42Z) did not record an SDK revision. The
inferred pin is agent-manifest `67c21db`, main at the run time; its
`python/src` and `examples` are identical to tag `python-v0.2.0` (`47355f3`).
Current main for the staleness run: `fed9aeb`.

## Clock

The committed example manifests expire on 2026-09-02 (level0, level1) and
2026-09-10 (hitl, multi-artifact). After those dates `bench.py` stops at its
VALID sanity assertion with `EXPIRED`. `run_frozen_clock.py` replaces
`datetime` inside the loaded `agent_manifest` modules with a subclass whose
`now()` returns the original run time, then calls `bench.main()`. Because
`bench.py` also reads that clock, `env.timestamp` in the saved JSON shows the
frozen time, not the rerun time (2026-10-01, about 18:50Z).

## Commands

Fresh venv, CPython 3.12.10 ARM64; copy `bench.py`, `run_frozen_clock.py` and
`hitl_probe.py` into one scratch directory so the committed results are not
overwritten:

    py -3.12-arm64 -m venv venv
    venv/Scripts/python -m pip install <agent-manifest@67c21db>/python
    PYTHONUTF8=1 AGENT_MANIFEST_ROOT=<agent-manifest@67c21db> venv/Scripts/python run_frozen_clock.py

## Results (three runs, `pin-arm64/bench-run{1,2,3}.json`)

| Manifest | Paper sign / verify med. ms | Rerun sign med. ms | Rerun verify med. ms | JCS bytes paper / rerun |
|---|---|---|---|---|
| level0 | 0.57 / 1.16 | 0.58 to 0.73 | 0.76 to 1.04 | 2018 / 2018 |
| multi_artifact | 1.46 / 1.55 | 0.88 to 1.08 | 1.12 to 1.58 | 2968 / 2968 |
| hitl | 0.71 / 1.18 | 0.50 to 0.55 | 0.77 to 0.88 | 2311 / 2311 |
| level1 | 1.97 / 2.66 | 1.35 to 1.67 | 3.89 to 4.91 | 4968 / 4968 |

Delegation chain, depth 1: 0.21 ms (paper 0.21); depth 10: 3.16 to 3.55 ms
(paper 2.96). Tamper: 10 of 10 cases caught in every run, as in the paper.
Sizes and tamper outcomes reproduce exactly. The level1 verify median does not
reproduce the paper's "verification under 2.7 ms"; package versions of the
original run (pydantic, cryptography) were not recorded, so the cause is not
attributable.

Post-quantum: not measurable. The SDK's `pq` extra names `pyoqs`, which is not
on PyPI.

## Main

`main-arm64/bench_frozen_clock.txt`: on current main the committed level0
example returns `MISMATCH` on `tool_manifest.catalog_hash` even with the clock
frozen. Since #418 (8070bbb, 2026-09-14) the verifier recomputes the declared
catalog root from the per-tool entries, and the example's declared root does
not match its own tool list. The example file is unchanged since the pin, so
the pinned verifier accepted an internally inconsistent catalog hash as VALID.

## HITL probe

`hitl_probe.py` signs the HITL example, replaces every approval's
`approver_id` and `approval_signature` with forged values, and re-verifies
without re-signing. At the pin the result is `VALID` with HITL `APPROVED`,
with and without `enforce_hitl` (`pin-arm64/hitl_probe.txt`): approvals are
normalized to `[]` in the signature pre-image and `verify_manifest` did not
check `approval_signature`. On main the HITL result is `UNVERIFIABLE` without
approver keys (36d0c89, 2026-08-22).
