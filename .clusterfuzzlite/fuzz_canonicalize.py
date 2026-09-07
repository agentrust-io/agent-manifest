#!/usr/bin/python3
"""Fuzz the canonicalizer for the invariant its signatures depend on.

canonicalize() produces the bytes that get signed, so the bytes must be a
faithful, lossless encoding of the input. The property asserted here is a round
trip: parsing the canonical output back must reproduce the input exactly.

This is the invariant #322 broke three ways. The sharpest was NFC normalization
of object keys: two distinct keys normalized to the same key, the output held
that key twice, and json.loads kept one of the pair, so a field vanished from a
document whose signature claimed to cover it. A round-trip check fails on that
input immediately, where a "does it crash" check passes.

Structure is built from the fuzz data rather than mutating JSON text, so the
fuzzer spends its budget on key and value shapes (combining marks, surrogate
pairs, control characters, integer boundaries) instead of on producing
syntactically valid JSON.
"""
import json
import math
import sys

import atheris

with atheris.instrument_imports():
    from agent_manifest._canonicalize import canonicalize

_MAX_DEPTH = 4
_MAX_ITEMS = 6


def _build(fdp: atheris.FuzzedDataProvider, depth: int = 0):
    if depth >= _MAX_DEPTH or fdp.remaining_bytes() == 0:
        return fdp.ConsumeUnicodeNoSurrogates(16)
    kind = fdp.ConsumeIntInRange(0, 7)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        # Straddle the safe-integer boundary deliberately: outside it,
        # canonicalize() must refuse rather than emit digits no conforming
        # verifier produces.
        return fdp.ConsumeIntInRange(-(2**54), 2**54)
    if kind == 3:
        return fdp.ConsumeFloat()
    if kind == 4:
        return fdp.ConsumeUnicodeNoSurrogates(64)
    if kind == 5:
        return [_build(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, _MAX_ITEMS))]
    return {
        fdp.ConsumeUnicodeNoSurrogates(24): _build(fdp, depth + 1)
        for _ in range(fdp.ConsumeIntInRange(0, _MAX_ITEMS))
    }


def _json_equal(a, b) -> bool:
    """Equality up to JSON's number model.

    JSON has a single number type, so a float whose shortest form has no
    fractional part re-parses as a Python int: 1.7900809247958546e+18
    canonicalizes to 1790080924795854600 and comes back as an int that does not
    compare equal to the float. That is correct RFC 8785 output, not a defect,
    so the round trip is asserted up to numeric type rather than exactly.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return float(a) == float(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _has_nonfinite(value) -> bool:
    """NaN and Infinity have no JSON form; canonicalize() rejects them by design."""
    if isinstance(value, float):
        return not math.isfinite(value)
    if isinstance(value, dict):
        return any(_has_nonfinite(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_nonfinite(v) for v in value)
    return False


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    value = _build(fdp)
    if _has_nonfinite(value):
        return
    try:
        out = canonicalize(value, exclude_none=False)
    except ValueError:
        # Declared: non-finite floats, integers outside the RFC 8785 safe
        # domain, and nesting past the depth limit.
        return

    assert _json_equal(json.loads(out), value), f"canonical bytes did not round-trip: {out!r}"
    assert canonicalize(value, exclude_none=False) == out, "canonicalization is not deterministic"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
