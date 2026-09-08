# Fuzzing

Coverage-guided fuzzing via [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/),
running Atheris against the SDK's untrusted input surface.

## What is fuzzed, and why these

A verifier reads all of the following before it has decided to trust anything
about the party that supplied them.

| Target | Surface |
| --- | --- |
| `fuzz_attestation_parsers.py` | SNP report, TDX quote, TPM quote and TPMT_SIGNATURE parsing. Fixed offsets and four levels of attacker-chosen declared length. |
| `fuzz_cose.py` | `verify_cose_manifest` and the other envelope decoders: CBOR tags, protected header, crit list, JSON payload. |
| `fuzz_canonicalize.py` | The bytes that get signed. |

## The properties

The parser targets assert that each function fails closed: it returns, or
raises the error type its own module declares. A `struct.error`, `IndexError`,
`MemoryError` or `OverflowError` reaching the caller means a length field was
believed, and a caller written against the documented exception will not catch
it.

`fuzz_canonicalize.py` asserts a round trip: parsing the canonical output must
reproduce the input. That is stronger than "does it crash", and deliberately so.
The three bugs behind #322 were all silent. The sharpest was NFC normalization
of object keys, where two distinct keys normalized to one, the output carried
that key twice, `json.loads` kept one of the pair, and a field disappeared from
a document whose signature claimed to cover it. Nothing crashed.

Equality is asserted up to JSON's number model, since JSON has one number type
and a large float legitimately re-parses as an int.

## Standing of the targets when added

`fuzz_cose.py` found a real bug on its first run: `_decode_tagged` never
type-checked the signature slot, so a stray break byte, which cbor2 decodes to a
bare `object()`, passed step 1 and blew up on re-encode in `attach_unprotected`
with `CBOREncodeError`, a type outside the `CoseError` hierarchy every caller is
written against. Fixed by checking the slot per tag; the reproducer is the
regression test.

`fuzz_attestation_parsers.py` found nothing. A local probe of 36,000 mutated
inputs across the nine parser entry points found no undeclared exception
escaping any of them, so that target is a regression guard rather than a hole
being closed.

`fuzz_canonicalize.py` has a demonstration behind it: run against the revision
before #322 was fixed it finds the round-trip violation in about ten seconds,
and against the fix it is clean over 29,997 generated documents.

## Bundling gotcha

`compile_python_fuzzer` bundles each target with PyInstaller, which follows
static imports only. The cryptography and pydantic stacks reach `email.mime`
lazily, so the bundled target dies at runtime with
`ModuleNotFoundError: No module named 'email.mime'` and libFuzzer reports that
as a crash in the target rather than a build problem. `build.sh` passes
`--collect-submodules=email` for this. A new dependency with a lazy import can
need the same treatment.

## Running locally

```
git clone https://github.com/google/clusterfuzzlite --depth 1 /tmp/clusterfuzzlite
python /tmp/clusterfuzzlite/infra/helper.py build_image --external $PWD
python /tmp/clusterfuzzlite/infra/helper.py build_fuzzers --external --sanitizer address $PWD
python /tmp/clusterfuzzlite/infra/helper.py run_fuzzer --external $PWD fuzz_canonicalize
```

A crash is written to a file whose path the runner prints; pass that file back
as the last argument to reproduce it.

## In CI

`cflite_pr.yml` fuzzes only code the pull request touched, for five minutes.
`cflite_batch.yml` runs every target for an hour, nightly. Both are read-only
and report through the job log and the crash artifact rather than as
code-scanning alerts.
