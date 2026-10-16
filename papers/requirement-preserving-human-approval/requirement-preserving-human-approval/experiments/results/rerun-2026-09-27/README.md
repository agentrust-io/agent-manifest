# September 27, 2026 rerun

- `pinned/`: `reproduce.py` and `boundary_probes.py` against `git archive` extracts of the
  three pinned commits (agentrust-telemetry 29c13cf, weight-custody-manifest 2acedfa,
  agent-manifest 9348097). The runner checked each tar's embedded commit id before extracting.
  `results.json` records the interpreter version, package versions, commands and log hashes.
- `later-revision/`: `boundary_probes.py` only, against `git archive` extracts of the
  commits listed in `COMMITS.txt` (origin/main on September 27, 2026). The repository
  test suites were not run at these commits.

Environment: Windows, Python 3.12.10, pytest 8.4.2, cryptography 50.0.0, jsonschema 4.26.0,
cbor2 5.9.0. The September 4 run used cbor2 6.1.4; local application control blocks the
6.x compiled extension on this machine. The selected test modules do not test COSE or CBOR encoding.

Logs have local paths replaced with `<source-root>`, `<python-prefix>` and `<home>`.
Software only: no protected hardware, durable store or external identity provider.
