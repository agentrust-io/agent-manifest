from __future__ import annotations

from agent_manifest._canonicalize import canonicalize


def test_shared_canonicalizer_now_orders_keys_by_utf16_code_units() -> None:
    """Keep the resolved #322 dependency visible at the assessment boundary."""
    value = {"\ue000": 2, "😀": 1}
    assert canonicalize(value) == '{"😀":1,"\ue000":2}'.encode()


def test_shared_canonicalizer_now_normalizes_exponent_leading_zero() -> None:
    """Current upstream fixed the exponent spelling used by assessment digests."""
    assert canonicalize(1e-7) == b"1e-7"


def test_rfc8785_does_not_overescape_line_separator() -> None:
    """The last escaping axis of #322, now resolved.

    U+2028 is not escaped by ECMAScript QuoteJSONString, which RFC 8785
    section 3.2.2.2 defers to, so escaping it here diverged from every
    conforming implementation.
    """
    assert canonicalize({"value": "\u2028"}) == '{"value":"\u2028"}'.encode()
