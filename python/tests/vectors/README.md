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

### COSE vectors (manifest version 0.2)

A vector carries **either** `manifest` or `envelope_hex`, never both. The
envelope follows the manifest `version` (ADR-0011), so which key is present
tells a consumer which verification procedure applies: `manifest` is a v0.1
document with a detached signature block, `envelope_hex` is a v0.2 COSE object
as hex-encoded CBOR.

```jsonc
{
  "id": "AM-VEC-COSE-001",
  "envelope_hex": "d284586aa401270378...",   // tagged COSE_Sign1, CBOR
  "context": { ... },
  "expected": {
    "result": "VALID",
    "signature_verified": true,
    "cose": {                      // the encoding, pinned element by element
      "tag": 18,                   // COSE_Sign1; 98 would be COSE_Sign
      "protected_hex": "a4012703...",
      "unprotected_hex": "a0",     // zero-length map, never omitted
      "payload_hex": "7b2261...",  // RFC 8785 canonical JSON of the manifest
      "signature_hex": "...",
      "manifest_hash": "sha256:..." // what hardware attestation binds
    }
  }
}
```

The `cose` block is the point of these vectors: an implementation must produce
**these exact bytes**, not merely something its own verifier accepts. Decode
`payload_hex` as JSON to read the manifest under test.

Only Ed25519 envelopes can be pinned this way. ML-DSA-65 signing is hedged, so
a post-quantum or hybrid envelope differs on every run and only its structure
is stable. There is deliberately no post-quantum COSE vector: one whose bytes
changed on every regeneration would be a snapshot rather than a contract, and
shipping a private seed for consumers to regenerate against would break the
rule below that no private key material is written to disk.

### Negative COSE vectors

`AM-VEC-COSE-002` onward are envelopes a conforming verifier **must not
accept**. They carry `envelope_hex` and an expected result, and deliberately
**no `expected.cose` block**: the bytes are malformed by construction, so
pinning their decomposition would assert that a verifier can parse something
it is being told to reject.

```jsonc
{
  "id": "AM-VEC-COSE-003",
  "description": "alg present in the unprotected header is rejected, never read.",
  "envelope_hex": "d284586aa401270378...",
  "context": { ... },
  "expected": {
    "result": "MISMATCH",
    "signature_verified": false
  }
}
```

Consume them exactly as the positive ones: decode `envelope_hex` and run your
verifier over the bytes. The only difference is what you assert.

Two properties are worth knowing before you rely on them.

**They state that a manifest is rejected, not why.** Every structural
rejection maps to `MISMATCH`, so a verifier that rejects one of these for the
wrong reason still passes. Each vector's `description` and `spec_refs` name
the rule actually under test, and an implementation that wants stronger
assurance should check it rejects for that reason.

**One of them expects `VALID`.** `AM-VEC-COSE-005` injects an unprotected
header after signing, and a conforming verifier must still return `VALID`,
because nothing in the unprotected header is covered by the signature and
section 6 step 7 evaluates it last. A verifier that merged the two halves, or
read `kid` from the malleable one, fails it. It is filed with the negatives
because it tests the same rule from the other side.

`context` maps field-for-field onto the SDK's `VerificationContext`, so a Python
consumer is just `VerificationContext(**vector["context"])`. Other languages
should treat each key as a named verification input.

## How a verifier consumes these

1. Read `keys.json` for the issuer public key (`public_key_b64url`, `key_id`).
2. For each vector: build your verification context from `context`; if
   `revoke` is set, mark `manifest.manifest_id` revoked first.
3. Run your verifier over `manifest`, or over the CBOR bytes of
   `envelope_hex` when that key is present instead.
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

`AM-VEC-001` … `AM-VEC-020` span the full `OverallResult` space:

* `VALID` — happy path; valid signed delegation chain; matching attestation report.
* `MISMATCH` — artifact hash, tampered signature, flagged RAG poisoning scan,
  crypto-profile downgrade (post-quantum profile, classical-only signature).
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
