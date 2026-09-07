# Testing RFC 8785 canonicalization in PyCharm

This guide explains how to run the issue #322 checks locally. It assumes the
repository is already open in PyCharm and Python is installed.

## 1. Configure the Python interpreter

1. Open **Settings > Project > Python Interpreter**.
2. Select an existing Python 3.11+ interpreter, or create a virtual
   environment for this project.
3. Set the project or run-configuration working directory to the repository's
   `python` directory.

## 2. Install the project

Open the PyCharm **Terminal** and run:

```powershell
cd python
python -m pip install -e ".[dev]"
```

## 3. Run the focused tests

Run the canonicalization unit tests:

```powershell
python -m pytest tests/test_canonicalize.py -q
```

Run the independent trace-spec boundary guard:

```powershell
python -m pytest tests/interop/test_trace_canonicalization_boundary.py -v
```

The boundary guard verifies four signed records. It tests the exact signing
pre-image, not only expected strings written in the test.

In PyCharm, right-click either test file in the Project pane and choose
**Run pytest**. If PyCharm cannot import `agent_manifest`, confirm that the
working directory is `python` and that the editable install completed.

## 4. Run the full suite

After the focused tests pass, run:

```powershell
python -m pytest -q
```

The expected result is no failures. Skipped tests are acceptable when they
require optional hardware or external services.

## 5. Check your local changes

Use **Git > Show History** or the terminal:

```powershell
git status --short
git diff -- docs/adr/0003-rfc9162-merkle-domain-separation.md
```

The signed JSON vectors are byte-sensitive fixtures. Do not retype or
reformat them. This local follow-up should contain the ADR, the interop test,
the four vectors and their README, and this guide; the canonicalizer itself is
already fixed on the base branch.

## What the guard proves

The vectors cover non-ASCII values, non-BMP values, and UTF-16 object-key
ordering. If the canonicalizer regresses, Ed25519 verification fails even
though the record and public key are unchanged.
