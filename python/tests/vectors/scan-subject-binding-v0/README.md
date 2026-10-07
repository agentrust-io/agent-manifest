# scan-subject-binding-v0 (vendored fixture, CC0)

Source: `conformance/scan-subject-binding-v0/vectors.json` at
babyblueviper1/recompute-kit@e78eb1d9ba6425601e43ca17953c8e321801e2ab (under review as trustless-ai/recompute-kit#59), CC0 1.0.
sha256 `eab2b61c37e57bc697957ed7f26cf48cc097a519fc1f4a8ea71b3d06cc026562`. Vendored unchanged for issue #472.

`tests/test_poisoning_scan.py` uses the two cases that the manifest-level rule decides (the suite's other cases are verifier-side:
effective-set binding, inclusion-proof transfer, scanner semantics, evidence grading):

- `c1_scan_of_A_presented_with_B_unbound`: corpus B's `merkle_root` with corpus A's clean scan, no `subject_digest`.
  Level 1+: not VALID (subject_digest REQUIRED). Level 0: VALID, as section 3.2.5 permits an absent digest there.
- `c1b_scan_of_A_presented_with_B_bound`: the same scan carrying A's root as `subject_digest` next to B's `merkle_root`.
  Not VALID at any level, and its `clean` result is not read as a statement about B.

Corpus B is corpus A plus one inserted document; in the suite the decision's answer flips from `10000 USD` to `1000000 USD` while
every signature and Merkle root verifies (c0).
