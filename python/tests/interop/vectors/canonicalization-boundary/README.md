# Vendored trace-spec canonicalization-boundary vectors

The four JSON files in this directory are signed fixtures copied from
trace-spec's `examples/canonicalization-boundary` set. They are intentionally
stored as raw fixture bytes rather than retyped so the guard catches
canonicalization differences that a hand-created test could hide.

Run the guard from the `python` directory:

```powershell
python -m pytest tests/interop/test_trace_canonicalization_boundary.py -v
```

The test verifies all four records with their Ed25519 signatures. If a fixture
is ever missing, the test skips and this directory should be restored from the
repository's approved fixture source before relying on the result.
