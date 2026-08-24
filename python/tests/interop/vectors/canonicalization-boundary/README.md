# Vendored trace-spec canonicalization-boundary vectors

Empty until fetched. `test_trace_canonicalization_boundary.py` skips with
fetch instructions when no `*.json` files are present here.

Source: https://github.com/agentrust-io/trace-spec/tree/main/examples/canonicalization-boundary

These are signed fixtures — fetch the raw bytes directly rather than
retyping them, since the guard exists to catch canonicalization differences
that a retyped copy could silently hide.

```powershell
git clone --depth 1 https://github.com/agentrust-io/trace-spec C:\Temp\trace-spec
Copy-Item C:\Temp\trace-spec\examples\canonicalization-boundary\*.json .
```

or per file:

```powershell
curl.exe -o 01-non-ascii-values.json https://raw.githubusercontent.com/agentrust-io/trace-spec/main/examples/canonicalization-boundary/01-non-ascii-values.json
curl.exe -o 02-non-bmp-values.json https://raw.githubusercontent.com/agentrust-io/trace-spec/main/examples/canonicalization-boundary/02-non-bmp-values.json
curl.exe -o 03-utf16-key-order.json https://raw.githubusercontent.com/agentrust-io/trace-spec/main/examples/canonicalization-boundary/03-utf16-key-order.json
curl.exe -o 04-utf16-key-order-nested.json https://raw.githubusercontent.com/agentrust-io/trace-spec/main/examples/canonicalization-boundary/04-utf16-key-order-nested.json
```

Run `pytest tests/interop/test_trace_canonicalization_boundary.py -v` afterward.
