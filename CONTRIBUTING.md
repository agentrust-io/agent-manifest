# Contributing to Agent Manifest

Agent Manifest is an open specification and reference SDK. Contributions are welcome in three areas: the specification, the Python SDK, and the conformance test suite.

## Before you start

The spec is in active design-partner review, and in CoSAI WS4 Phase 1 review ahead of a proposed contribution to WS4. Breaking spec changes (field renames, schema incompatibilities, conformance level changes) require an issue and discussion before a PR. Non-breaking additions and bug fixes can go straight to a PR.

## Using AI to contribute

Use agents. A lot of this was built with them and saying otherwise would be dishonest.

The rule is that you have to understand what you submit. If you cannot explain what your change does and how it interacts with the rest of the system, with the agent closed, do not open the pull request. Reviewing a change nobody can explain costs more than writing it did, and it becomes someone else's problem the moment it merges.

That is a rule about understanding, not about tooling.

## Being vouched

If you have not contributed here before, ask before you build. Open an issue saying what you want to change and why, in your own words. A maintainer will reply and add you with `/vouch`, and after that your pull requests go through the normal review.

A pull request from an account that has not been vouched is closed automatically, with a comment pointing back here. That is not a judgement about you or about the change. It exists because agent-written contributions are cheap to produce and expensive to review, and a short conversation first is better for both sides than a review neither of us can finish.

Anyone who can already push, and anyone with a merged pull request here before this rule existed, is already vouched.

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

Pytest is configured to import `python/src` ahead of any globally installed
`agent-manifest` wheel. A regression guard fails if the suite resolves the
package outside the checkout, so local results always exercise the code under
review.

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

### Release artifact verification

The PyPI workflow builds one wheel and one source distribution, installs each
with the declared `cli` extra into a separate clean virtual environment, and runs
`scripts/verify_python_distribution.py` outside the checkout. The gate checks
the installed metadata version, proves imports do not resolve to `python/src`,
exercises the public signing and verification API, and invokes the packaged
`manifest` console entry point. Neither artifact is uploaded unless both pass.
The main CI path filters include release scripts and workflow definitions so
changes to this gate cannot bypass the repository's normal review checks.

## Submitting a PR

1. Fork the repo and create a branch from `main`.
2. Write tests for any SDK changes. Conformance test IDs (e.g. `AM-BIND-001`) must be referenced in the test docstring.
3. Ensure `pytest`, `mypy`, and `ruff check` all pass locally.
4. Open a PR against `main`. Fill in the PR template.
5. One maintainer approval is required to merge.

## Spec changes

Read [who may author normative text](https://github.com/agentrust-io/agent-manifest/blob/main/GOVERNANCE.md#who-may-author-normative-text) first. Normative changes, meaning anything with an uppercase RFC 2119 keyword, need an organizational sponsor accountable for the requirement. Anyone may propose one, and a Maintainer carries the PR for an accepted proposal that has no sponsor. Everything else, including informative crosswalks and mappings to external schemas such as OCSF, needs no sponsor.

Spec changes follow this process:

1. Open a GitHub issue describing the problem and proposed change. Reference the spec section.
2. Allow 5 business days for design-partner feedback.
3. Submit a PR against the [current specification](https://github.com/agentrust-io/agent-manifest/blob/main/spec/README.md) with the change marked using `<!-- CHANGED: ISSUE-NNN — description -->`.
4. Update conformance tests in `python/tests/` to cover the changed normative text.
5. Update `CHANGELOG.md`.

## Issue types

Use the issue templates:
- **Bug report** — incorrect behavior in the SDK or test suite
- **Spec change proposal** — normative text issues, gaps, or ambiguities

For security issues, see [SECURITY.md](https://github.com/agentrust-io/agent-manifest/blob/main/SECURITY.md).

## Code conventions

- Python 3.11+ syntax; strict mypy types required
- Pydantic v2 for all data models
- No external dependencies beyond those in `pyproject.toml`
- Test files must map to spec modules: `test_am_bind.py`, `test_am_crypto.py`, etc.
- Commit messages: `type(scope): short description` (conventional commits)

## License

By contributing you agree that your contributions will be licensed under the Apache 2.0 license.
