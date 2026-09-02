from __future__ import annotations

import pytest

from agent_manifest._canonicalize import canonicalize


_REMAINING_BLOCKER = pytest.mark.xfail(
    strict=True,
    reason=(
        "agent-manifest#322: current main still over-escapes U+2028, so the "
        "shared canonicalizer is not yet fully RFC 8785 conformant"
    ),
)


def test_shared_canonicalizer_now_orders_keys_by_utf16_code_units() -> None:
    """Keep the resolved #322 dependency visible at the assessment boundary."""
    value = {"\ue000": 2, "😀": 1}
    assert canonicalize(value) == '{"😀":1,"\ue000":2}'.encode()


def test_shared_canonicalizer_now_normalizes_exponent_leading_zero() -> None:
    """Current upstream fixed the exponent spelling used by assessment digests."""
    assert canonicalize(1e-7) == b"1e-7"


@_REMAINING_BLOCKER
def test_rfc8785_does_not_overescape_line_separator() -> None:
    """Retain a strict guard for the unresolved escaping axis of #322."""
    assert canonicalize({"value": "\u2028"}) == '{"value":"\u2028"}'.encode()
