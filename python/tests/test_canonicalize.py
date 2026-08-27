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


def test_utf16_code_unit_key_order_not_code_point_order():
    # RFC 8785 §3.2.3 sorts by UTF-16 code unit. U+10000 (a supplementary-
    # plane character) is a surrogate pair D800 DC00 in UTF-16, which sorts
    # below the BMP character U+FFFF (code unit FFFF) — the reverse of code
    # point order, where U+10000 > U+FFFF. Issue #322.
    obj = {chr(0x10000): 1, chr(0xFFFF): 2}
    result = canonicalize(obj)
    expected = ('{"' + chr(0x10000) + '":1,"' + chr(0xFFFF) + '":2}').encode("utf-8")
    assert result == expected


def test_utf16_code_unit_key_order_nested():
    # Same divergence one level deep, matching trace-spec's
    # 04-utf16-key-order-nested.json boundary vector.
    obj = {"outer": {chr(0x10000): 1, chr(0xFFFF): 2}}
    result = canonicalize(obj)
    assert result == (
        '{"outer":{"' + chr(0x10000) + '":1,"' + chr(0xFFFF) + '":2}}'
    ).encode("utf-8")


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


def test_line_separator_not_escaped():
    # RFC 8785 §3.2.2.2 defers to ECMAScript JSON.stringify, which escapes
    # only the quote, the reverse solidus, and U+0000-U+001F. U+2028 LINE
    # SEPARATOR is a hazard when JSON is pasted into JavaScript *source*, not
    # a JSON serialization rule — it MUST be emitted literally. This test
    # previously asserted the opposite (non-conformant) behaviour. Issue #322.
    assert canonicalize({"v": chr(0x2028)}) == ('{"v":"' + chr(0x2028) + '"}').encode("utf-8")


def test_paragraph_separator_not_escaped():
    assert canonicalize({"v": chr(0x2029)}) == ('{"v":"' + chr(0x2029) + '"}').encode("utf-8")


def test_delete_and_c1_controls_not_escaped():
    # U+007F (DELETE) and the C1 control range (U+0080-U+009F) are outside
    # ECMAScript JSON.stringify's escape set and must be emitted literally.
    assert canonicalize({"v": chr(0x7F)}) == ('{"v":"' + chr(0x7F) + '"}').encode("utf-8")
    assert canonicalize({"v": chr(0x85)}) == ('{"v":"' + chr(0x85) + '"}').encode("utf-8")


def test_regular_unicode_verbatim():
    # Non-control chars pass through after NFC normalization
    assert canonicalize({"v": "é"}) == '{"v":"é"}'.encode("utf-8")


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
# ECMAScript Number::toString formatting — issue #322 differential table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (1e-7, "1e-7"),
        (3e-8, "3e-8"),
        (-1e-7, "-1e-7"),
        (1e-6, "0.000001"),
        (1e-5, "0.00001"),
        (1e15, "1000000000000000"),
        (1e16, "10000000000000000"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (123.456, "123.456"),
        (100.5, "100.5"),
        (0.1, "0.1"),
        (1.0, "1"),
        (100.0, "100"),
        (0.0, "0"),
        (-0.0, "0"),
    ],
)
def test_float_formatting_matches_ecmascript_number_tostring(value, expected):
    assert canonicalize({"v": value}) == ('{"v":' + expected + "}").encode("utf-8")


def test_float_exponent_no_leading_zero_or_plus_padding():
    # Python's repr pads exponents to two digits and always signs them
    # ("1e-07"); RFC 8785 has neither a minimum width nor a leading zero.
    result = canonicalize({"v": 1e-7})
    assert result == b'{"v":1e-7}'
    assert b"1e-07" not in result


def test_integer_within_safe_range_serializes():
    assert canonicalize({"v": (1 << 53) - 1}) == b'{"v":9007199254740991}'


def test_large_integer_allowed():
    result = canonicalize(
        {"v": 295147905179352830000}
    )
    assert result == b'{"v":295147905179352830000}'


def test_large_integer_timestamp_allowed():
    assert canonicalize(
        {"timestamp_ns": 1790000000000000000}
    ) == b'{"timestamp_ns":1790000000000000000}'


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
