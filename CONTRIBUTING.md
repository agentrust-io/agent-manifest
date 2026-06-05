# Contributing to Agent Manifest

Agent Manifest is an open specification and reference SDK. Contributions are welcome in three areas: the specification, the Python SDK, and the conformance test suite.

## Before you start

The spec is in active design-partner review ahead of AAIF submission. Breaking spec changes (field renames, schema incompatibilities, conformance level changes) require an issue and discussion before a PR. Non-breaking additions and bug fixes can go straight to a PR.

## DCO sign-off

All commits must be signed off with the [Developer Certificate of Origin](https://developercertificate.org/):

```
git commit -s -m "feat: add foo"
```

This adds `Signed-off-by: Your Name <you@example.com>` to the commit. PRs without DCO sign-off will not be merged.

## Development setup

```bash
git clone https://github.com/agentrust-io/agent-manifest
cd agent-manifest/python
pip install -e ".[dev]"
```

Run tests:

```bash
pytest -v
```

Run type checking:

```bash
mypy src/agent_manifest
```

Run linting:

```bash
ruff check src/ tests/
```

Run security scan:

```bash
bandit -r src/agent_manifest
```

## Submitting a PR

1. Fork the repo and create a branch from `main`.
2. Write tests for any SDK changes. Conformance test IDs (e.g. `AM-BIND-001`) must be referenced in the test docstring.
3. Ensure `pytest`, `mypy`, and `ruff check` all pass locally.
4. Open a PR against `main`. Fill in the PR template.
5. One maintainer approval is required to merge.

## Spec changes

Spec changes follow this process:

1. Open a GitHub issue describing the problem and proposed change. Reference the spec section.
2. Allow 5 business days for design-partner feedback.
3. Submit a PR to `spec/agent-manifest-spec-v0.1.md` with the change marked using `<!-- CHANGED: ISSUE-NNN — description -->`.
4. Update conformance tests in `python/tests/` to cover the changed normative text.
5. Update `CHANGELOG.md`.

## Issue types

Use the issue templates:
- **Bug report** — incorrect behavior in the SDK or test suite
- **Spec change proposal** — normative text issues, gaps, or ambiguities

For security issues, see [SECURITY.md](SECURITY.md).

## Code conventions

- Python 3.11+ syntax; strict mypy types required
- Pydantic v2 for all data models
- No external dependencies beyond those in `pyproject.toml`
- Test files must map to spec modules: `test_am_bind.py`, `test_am_crypto.py`, etc.
- Commit messages: `type(scope): short description` (conventional commits)

## License

By contributing you agree that your contributions will be licensed under the Apache 2.0 license.
