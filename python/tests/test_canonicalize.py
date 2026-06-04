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
# @context / @type as ordinary fields
# ---------------------------------------------------------------------------


def test_context_type_ordinary():
    obj = {
        "@context": "https://agentmanifest.agentrust.io/v0.1/context.json",
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
