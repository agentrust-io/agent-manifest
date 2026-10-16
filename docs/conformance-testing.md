# Running and citing the reference conformance tests

The five `AM-*` names identify modules, not registered per-test selectors.
Historical labels such as `AM-BIND-015` in prose and docstrings were not a
one-to-one test registry and cannot be selected with `pytest -k`. Cite the
repository revision, module path and complete pytest node ID, including its
parameter suffix. Portable `AM-VEC-*` fixture IDs remain unchanged.

From a development environment with the repository's dependencies installed:

```bash
python scripts/conformance_inventory.py
cd python
python -m pytest tests/test_am_crypto.py::test_merkle_domain_separation -q
python -m pytest tests/test_am_crypto.py::test_ed25519_small_order_key_rejected -q
```

`docs/conformance-inventory.json` contains every collected node ID and module
count. The check derives it from pytest collection, including parametrized
cases, rather than counting `def test_` declarations. CI checks the inventory.
After adding, removing or parametrizing a module test, regenerate it with
`python scripts/conformance_inventory.py --write`, reconcile the counts in
spec section 8.2, the overview, README and roadmap, and review the diff.

A collection count is not a passing run, a level-specific distribution, complete
requirement coverage or evidence of hardware execution. Report passed and
skipped cases separately, including the environment and exact source revision.
The historical 197-test allocation and 89/51/42/15 level distribution are not a
mapping of the implemented suite. No exhaustive-coverage claim follows from
the current inventory.
