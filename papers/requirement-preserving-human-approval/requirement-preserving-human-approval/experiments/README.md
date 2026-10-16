# Experiments

Run from this directory, with the dependencies listed in
`results/rerun-2026-10-01/requirements-freeze.txt` (Python 3.12):

```
python reproduce.py --prepare-from /path/to/clones --source-root /path/to/empty-dir --output out
python boundary_probes.py --source-root /path/to/empty-dir --output out
```

`--prepare-from` takes a directory holding clones of agentrust-telemetry,
weight-custody-manifest and agent-manifest. It runs `git archive` of each pinned commit
(no checkout, no branch switch), checks the commit id embedded in the tar and extracts it.
Alternatively point `--source-root` at checkouts that are already at the pinned commits with
clean tracked files. The runner refuses any other revision. Outputs contain no absolute paths.

The runner covers three related reports; this paper relies on approval-tests.txt and on the
matching entries in `boundary-probes.json`. `boundary_probes.py` records what each probe
observed instead of asserting, so it can also be run against later revisions.

Neither script reproduces the historical protected-hardware receipt. `reproduce.py` and
`boundary_probes.py` are identical copies of the files in `../../_paper-assets/`.
