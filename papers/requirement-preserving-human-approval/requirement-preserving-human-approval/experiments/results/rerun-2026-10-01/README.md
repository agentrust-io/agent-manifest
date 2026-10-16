# October 1, 2026 rerun

Fresh Python 3.12.10 virtual environment on Windows 11, created for this run. Installed
packages are in `requirements-freeze.txt`; the direct pins were pytest 8.4.2, cryptography
50.0.0, pydantic 2.13.4, jsonschema 4.26.0, referencing 0.37.0, rfc8785 0.1.4, cbor2 5.9.0,
agentrust-trace 0.9.0, opentelemetry-sdk 1.44.0, jcs 0.2.1 and PyYAML 6.0.3 (the September 27
set). Fresh clones of agentrust-telemetry, weight-custody-manifest and agent-manifest were taken
the same day.

## pinned/

Run from `experiments/`:

```
python reproduce.py --prepare-from CLONES --source-root PINNED_SRC --output OUT
python boundary_probes.py --source-root PINNED_SRC --output OUT
```

`reproduce.py` built each source tree with `git archive` of the pinned commit and checked the
commit id embedded in the tar (agent-manifest 934809709a28, agentrust-telemetry 29c13cfa4047,
weight-custody-manifest 2acedfa88320). Both commands exited 0.

| Task | Result |
|---|---|
| approval-tests (agent-manifest `test_signing.py`, `test_delegation_hitl.py`) | 74 passed, 1 warning (`asyncio_mode` config option unknown without pytest-asyncio) |
| telemetry-tests | 111 tests, OK |
| telemetry-conformance | 13 of 13 fixtures returned the expected verdict |
| memory-tests | 35 passed |

The boundary probes returned the same observations as the September 27 rerun. For this paper:
`approval_signer_accepts_method_parameter` false, `approval_method_label_is_outside_approval_signature`
true, `approval_unaltered_verifies` true, `approval_helper_accepts_zero_or_missing_duration` true,
`requirement_bound_approval_appendable` true.

## later-revision/

`boundary_probes.py` against `git archive` extracts of the September 27 later revision
(agent-manifest 3c124914e3dc, weight-custody-manifest 94d5519fd604, agentrust-telemetry
c3515681261f). Same observations as the September 27 record: the signer takes
`approval_method`, the label change fails verification, zero or absent durations are rejected,
requirement binding and appendability hold.

## main/

`origin/main` on October 1, 2026: agent-manifest fed9aeb091e4 (python-v0.15.0 plus one
unreleased fix), agentrust-telemetry c86753cad6bb, weight-custody-manifest 5ef8c122479f, each
extracted with `git archive` and the tar commit id checked.

- `boundary-probes.json`: same five approval observations as `later-revision/`.
- `approval-tests.txt`: the same two agent-manifest modules, run as
  `python -m pytest -p no:cacheprovider -o pythonpath=src tests/test_signing.py tests/test_delegation_hitl.py -v`
  from `agent-manifest/python`. 146 passed, 1 warning. The modules have grown since the pin,
  so this count is not comparable with 74.

Logs have local paths replaced with `<source-root>` and `<python-prefix>`. Software only: no
hardware authenticator, external identity provider or protected action execution.
