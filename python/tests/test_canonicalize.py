"""RFC 8785 canonical JSON test suite.

Covers:
  - Appendix D test vector (verified via sha256sum)
  - Key sort ordering, whitespace, null exclusion
  - NFC normalization, string escaping, boolean/float handling
  - @context / @type as ordinary fields
"""
import hashlib
import math

import pytest
from agent_manifest._canonicalize import canonical_hash, canonicalize

# ---------------------------------------------------------------------------
# Spec Appendix D test vector (SHA-256 verified via bash sha256sum)
# ---------------------------------------------------------------------------

APPENDIX_D_INPUT = {
    "version": "0.1",
    "issued_at": "2026-06-23T09:00:00Z",
    "agent_id": "spiffe://trust.example/agent/kyc/prod-001",
}
APPENDIX_D_CANONICAL = (
    b'{"agent_id":"spiffe://trust.example/agent/kyc/prod-001"'
    b',"issued_at":"2026-06-23T09:00:00Z","version":"0.1"}'
)
APPENDIX_D_SHA256 = "b83293348255f4427dc030478f354b83f4f82662223be0926ad9f2db946b5319"


def test_appendix_d_canonical_form():
    assert canonicalize(APPENDIX_D_INPUT) == APPENDIX_D_CANONICAL


def test_appendix_d_sha256():
    assert hashlib.sha256(APPENDIX_D_CANONICAL).hexdigest() == APPENDIX_D_SHA256


def test_appendix_d_canonical_hash():
    assert canonical_hash(APPENDIX_D_INPUT) == f"sha256:{APPENDIX_D_SHA256}"


# ---------------------------------------------------------------------------
# Key ordering
# ---------------------------------------------------------------------------


def test_keys_sorted_lexicographic():
    assert canonicalize({"z": 1, "a": 2, "m": 3}) == b'{"a":2,"m":3,"z":1}'


def test_nested_keys_sorted():
    assert canonicalize({"b": {"y": 1, "x": 2}, "a": 0}) == b'{"a":0,"b":{"x":2,"y":1}}'


def test_unicode_key_ordering():
    # chr(233) = U+00E9 (é) > chr(101) = 'e'
    obj = {chr(233): 1, "e": 2}
    result = canonicalize(obj)
    assert result == ('{"e":2,"' + chr(233) + '":1}').encode("utf-8")


# ---------------------------------------------------------------------------
# Whitespace
# ---------------------------------------------------------------------------


def test_no_whitespace():
    result = canonicalize({"a": 1, "b": [1, 2, 3]})
    assert b" " not in result and b"\n" not in result and b"\t" not in result


# ---------------------------------------------------------------------------
# Null handling (spec Section 4.3)
# ---------------------------------------------------------------------------


def test_null_excluded_by_default():
    assert canonicalize({"a": 1, "b": None, "c": 3}) == b'{"a":1,"c":3}'


def test_null_included_when_opted_in():
    assert canonicalize({"a": 1, "b": None}, exclude_none=False) == b'{"a":1,"b":null}'


def test_nested_null_excluded():
    assert canonicalize({"outer": {"present": 1, "absent": None}}) == b'{"outer":{"present":1}}'


# ---------------------------------------------------------------------------
# Boolean serialization
# ---------------------------------------------------------------------------


def test_boolean_true():
    assert canonicalize({"v": True}) == b'{"v":true}'


def test_boolean_false():
    assert canonicalize({"v": False}) == b'{"v":false}'


def test_bool_not_confused_with_int():
    # bool is a subclass of int — must not serialize True as 1
    assert canonicalize({"a": True, "b": 1}) == b'{"a":true,"b":1}'


# ---------------------------------------------------------------------------
# String escaping — using chr() to avoid embedding control chars in source
# ---------------------------------------------------------------------------


def test_null_byte_escaped():
    assert canonicalize({"v": chr(0)}) == b'{"v":"\\u0000"}'


def test_unit_separator_escaped():
    assert canonicalize({"v": chr(31)}) == b'{"v":"\\u001f"}'


def test_backslash_escaped():
    assert canonicalize({"v": "\\"}) == b'{"v":"\\\\"}'


def test_double_quote_escaped():
    assert canonicalize({"v": '"'}) == b'{"v":"\\""}'


def test_tab_newline_escaped():
    assert canonicalize({"v": "\t\n"}) == b'{"v":"\\t\\n"}'


def test_line_separator_escaped():
    # U+2028 LINE SEPARATOR must be
    assert b"\\u2028" in canonicalize({"v": chr(0x2028)})


def test_regular_unicode_verbatim():
    # Non-control chars pass through after NFC normalization
    assert canonicalize({"v": "é"}) == '{"v":"é"}'.encode()


# ---------------------------------------------------------------------------
# NFC normalization
# ---------------------------------------------------------------------------


def test_nfc_normalization():
    precomposed = "é"         # é as single code point
    decomposed = "é"   # e + combining accent
    assert canonicalize({"v": precomposed}) == canonicalize({"v": decomposed})


# ---------------------------------------------------------------------------
# Arrays
# ---------------------------------------------------------------------------


def test_array_order_preserved():
    assert canonicalize([3, 1, 2]) == b"[3,1,2]"


def test_nested_array():
    assert canonicalize([[1, 2], [3, 4]]) == b"[[1,2],[3,4]]"


def test_empty_array():
    assert canonicalize([]) == b"[]"


def test_empty_object():
    assert canonicalize({}) == b"{}"


# ---------------------------------------------------------------------------
# Numbers
# ---------------------------------------------------------------------------


def test_integer():
    assert canonicalize({"v": 42}) == b'{"v":42}'


def test_negative_integer():
    assert canonicalize({"v": -7}) == b'{"v":-7}'


def test_float_integer_value_no_decimal():
    assert canonicalize({"v": 1.0}) == b'{"v":1}'


def test_float_nan_raises():
    with pytest.raises(ValueError, match="NaN"):
        canonicalize({"v": math.nan})


def test_float_infinity_raises():
    with pytest.raises(ValueError, match="Infinity"):
        canonicalize({"v": math.inf})


# ---------------------------------------------------------------------------
# Float formatting must match ECMA-262 Number::toString exactly (RFC 8785
# §3.2.2.3), not Python's own repr() notation choice the two diverge at
# several magnitude boundaries and in exponent zero-padding.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (1e-6, "0.000001"),   # ECMAScript keeps this fixed, not exponential
        (1e-7, "1e-7"),        # ECMAScript switches to exponential here
        (5e-8, "5e-8"),        # ...with NO leading zero on the exponent
        (-1e-7, "-1e-7"),
        (1e15, "1000000000000000"),
        (1e16, "10000000000000000"),   # Python's repr() already goes exponential here
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),        # ECMAScript's fixed/exponential boundary is 1e21
        (1.5e21, "1.5e+21"),
        (123456789012345680000.0, "123456789012345680000"),
        (0.0, "0"),
        (-0.0, "0"),
    ],
)
def test_float_matches_ecmascript_tostring(value, expected):
    assert canonicalize({"v": value}) == f'{{"v":{expected}}}'.encode()


def test_float_exponent_not_zero_padded():
    # Python's repr(1e-7) is "1e-07"; RFC 8785 requires ECMAScript's "1e-7".
    assert canonicalize({"v": 1e-7}) == b'{"v":1e-7}'


# ---------------------------------------------------------------------------
# Object-key ordering must use UTF-16 code-unit order (RFC 8785 §3.2.3 /
# ECMA-262 JSON.stringify), which differs from Python's default code-point
# order for any key with a character outside the Basic Multilingual Plane.
# ---------------------------------------------------------------------------


def test_key_sort_uses_utf16_code_unit_order():
    # U+1F600 is encoded in UTF-16 as the surrogate pair D83D DE00, whose
    # first code unit (0xD83D) is less than U+E000. Under plain code-point
    # comparison (Python's default `sorted()`), U+1F600 > U+E000 instead,
    # producing the opposite non-conformant order.
    supplementary = "\U0001F600"
    bmp_high = "\uE000"
    obj = {supplementary: 1, bmp_high: 2}
    result = canonicalize(obj)
    assert result.index(supplementary.encode()) < result.index(bmp_high.encode())


# ---------------------------------------------------------------------------
# @context / @type as ordinary fields
# ---------------------------------------------------------------------------


def test_context_type_ordinary():
    obj = {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "test",
    }
    result = canonicalize(obj)
    # '@' (U+0040) sorts before all letters, so @context comes first
    assert result.startswith(b'{"@context"')
    assert b'"@type"' in result
    assert b'"manifest_id"' in result


# ---------------------------------------------------------------------------
# shake256
# ---------------------------------------------------------------------------


def test_shake256_length():
    result = canonical_hash({"v": 1}, algorithm="shake256")
    assert result.startswith("shake256:")
    assert len(result) == len("shake256:") + 64


def test_unsupported_algorithm_raises():
    with pytest.raises(ValueError, match="Unsupported"):
        canonical_hash({"v": 1}, algorithm="md5")
