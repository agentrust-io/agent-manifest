# Agent Manifest verification conformance vectors

Language-neutral test vectors for the Agent Manifest **verification engine**
(spec Section 5). They exist so that an implementation in *any* language can
prove it agrees with the reference Python SDK on the same inputs.

Each vector is a self-contained JSON file: a signed manifest, the verification
context (runtime artifact hashes + trusted keys), and the expected
`VerificationResult`. A conforming verifier that loads the manifest and context
MUST produce the expected `result` and the listed `fields_verified` statuses.

## Files

| File | Purpose |
|------|---------|
| `index.json` | Suite metadata and the list of vectors |
| `keys.json` | The Ed25519 **public** key used to verify every vector |
| `AM-VEC-*.json` | One vector each |
| `generate.py` | Regenerates all of the above from the reference SDK |

## Vector schema

```jsonc
{
  "id": "AM-VEC-001",
  "description": "...",
  "spec_refs": ["5.3"],          // normative spec sections exercised
  "manifest": { ... },            // the manifest document under test
  "context": { ... },             // 1:1 with VerificationContext (incl. trusted_keys)
  "expected": {
    "result": "VALID",            // OverallResult
    "signature_verified": true,    // optional
    "attestation_verified": false, // optional
    "fields_verified": {           // optional subset to assert
      "system_prompt": "MATCH"
    }
  },
  "revoke": true                   // optional: seed the revocation store with
}                                  // manifest_id before verifying
```

`context` maps field-for-field onto the SDK's `VerificationContext`, so a Python
consumer is just `VerificationContext(**vector["context"])`. Other languages
should treat each key as a named verification input.

## How a verifier consumes these

1. Read `keys.json` for the issuer public key (`public_key_b64url`, `key_id`).
2. For each vector: build your verification context from `context`; if
   `revoke` is set, mark `manifest.manifest_id` revoked first.
3. Run your verifier over `manifest`.
4. Assert your overall result equals `expected.result`, and every entry in
   `expected.fields_verified` matches.

The Python reference assertion lives in
[`tests/test_vectors.py`](../test_vectors.py).

## Determinism guarantees

* **Fixed key.** All vectors are signed with one Ed25519 key derived from the
  seed `00 01 02 … 1f` (hardcoded in `generate.py`). Ed25519 is deterministic
  (RFC 8032), so the signature bytes are reproducible. Only the public key is
  published in `keys.json`; verifiers need nothing more, and no private key
  material is ever written to disk.
* **Stable over time.** Expiry, memory-baseline TTL, and HITL approval windows
  use absolute dates far in the past/future, so expected results don't drift
  with the wall clock.
* **Canonical pre-image.** Signatures cover the RFC 8785 (JCS) canonical JSON of
  the manifest's `signed_fields` — see `signing_pre_image` in the SDK. Matching
  this byte-for-byte across languages is the key interop requirement.

## Coverage

`AM-VEC-001` … `AM-VEC-019` span the full `OverallResult` space:

* `VALID` — happy path; valid signed delegation chain; matching attestation report.
* `MISMATCH` — artifact hash, tampered signature, flagged RAG poisoning scan.
* `EXPIRED`, `REVOKED`, `INCOMPATIBLE_VERSION`.
* `SIGNATURE_MISSING` (unsigned) and `UNVERIFIABLE` (no trusted keys; and a
  delegation chain present without keys to verify it).
* `INCOMPLETE` (bound artifact, no runtime hash, strict mode) and
  `ATTESTATION_UNAVAILABLE` (attestation enforced but absent).
* HITL approved / missing / expired, and memory-baseline TTL expiry.

> Note: `AM-VEC-013` returns overall `VALID` while `memory_baseline` is
> `EXPIRED` — this faithfully encodes the reference engine's behaviour (an
> expired baseline is surfaced per-field but is not, on its own, a hard
> verification failure).

## Regenerating

From the `python/` directory:

```bash
python -m tests.vectors.generate
```

Regenerate only when the engine's normative behaviour changes, and review the
diff. The generated files are committed so consumers don't need to run Python.
