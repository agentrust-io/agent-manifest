"""RFC 8785 JSON Canonicalization Scheme (JCS).

Reference: https://www.rfc-editor.org/rfc/rfc8785

Single canonicalization entry point for all signing, hashing, and Merkle
tree operations in the Agent Manifest SDK. Used for:

  - Manifest signature pre-image
  - manifest_hash_in_report pre-image
  - Memory snapshot hash input
  - Evidence pack hash input
  - Merkle tree leaf nodes containing JSON content

Per spec Section 4.3:
  - Null-valued optional fields are EXCLUDED from canonical form by default.
  - @context and @type are treated as ordinary JSON fields (no JSON-LD normalization).
  - Text artifact content (system_prompt, policy_bundle) is hashed as raw UTF-8
    NFC bytes, not as JSON — use hashlib directly for those, not this module.
"""
from __future__ import annotations

import decimal
import hashlib
import math
import unicodedata
from typing import Any


_MAX_DEPTH = 64  # DOS-006: prevent RecursionError from deeply nested JSON
_MAX_SAFE_INTEGER = (1 << 53) - 1  # ECMAScript Number.MAX_SAFE_INTEGER


def canonicalize(obj: Any, *, exclude_none: bool = True) -> bytes:
    """Return RFC 8785 canonical JSON bytes for *obj*.

    Args:
        obj: Any JSON-serializable Python value.
        exclude_none: When True (default, per spec Section 4.3), mapping
            entries whose value is None are omitted from the output.
            Set to False only when verifying round-trips with external
            producers that include explicit null fields.

    Returns:
        UTF-8 encoded bytes with no trailing newline.

    Raises:
        TypeError: If *obj* contains a type that cannot be serialized.
        ValueError: If a float value is NaN or Infinity, or nesting exceeds
            the maximum depth.
    """
    return _serialize(obj, exclude_none=exclude_none, depth=0).encode("utf-8")


def canonical_hash(obj: Any, *, algorithm: str = "sha256", exclude_none: bool = True) -> str:
    """Canonicalize *obj* and return a prefixed hex digest.

    Returns:
        String in HashValue format: ``"sha256:<64-hex>"`` or
        ``"shake256:<64-hex>"``.
    """
    data = canonicalize(obj, exclude_none=exclude_none)
    if algorithm == "sha256":
        digest = hashlib.sha256(data).hexdigest()
    elif algorithm == "shake256":
        digest = hashlib.shake_256(data).hexdigest(32)  # 256-bit = 32 bytes
    else:
        raise ValueError(f"Unsupported algorithm {algorithm!r}. Use 'sha256' or 'shake256'.")
    return f"{algorithm}:{digest}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialize(obj: Any, *, exclude_none: bool, depth: int) -> str:
    if depth > _MAX_DEPTH:
        raise ValueError(
            f"JSON nesting depth exceeds maximum of {_MAX_DEPTH}. "
            "The manifest contains deeply nested structures."
        )
    if obj is None:
        return "null"
    if isinstance(obj, bool):
        # bool check must come before int — bool is a subclass of int in Python
        return "true" if obj else "false"
    if isinstance(obj, int):
        if abs(obj) > _MAX_SAFE_INTEGER:
            raise ValueError(
                f"Integer {obj!r} exceeds the IEEE-754 safe integer range "
                "(+/-2^53-1). RFC 8785 numbers must round-trip through a "
                "double; encode larger values as a string instead."
            )
        return str(obj)
    if isinstance(obj, float):
        return _float_to_str(obj)
    if isinstance(obj, str):
        return _quote(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_serialize(v, exclude_none=exclude_none, depth=depth + 1) for v in obj) + "]"
    if isinstance(obj, dict):
        return _serialize_dict(obj, exclude_none=exclude_none, depth=depth + 1)
    raise TypeError(
        f"Object of type {type(obj).__name__!r} is not JSON-serializable under RFC 8785"
    )


def _serialize_dict(d: dict[str, Any], *, exclude_none: bool, depth: int) -> str:
    # RFC 8785 §3.2.3: sort keys by UTF-16 code unit, not code point. Python's
    # default str comparison is code-point order, which disagrees with this
    # exactly when a key contains a supplementary-plane character (see
    # _utf16_sort_key) — so sorted(d.keys()) alone is not conformant.
    parts: list[str] = []
    for k in sorted(d.keys(), key=_utf16_sort_key):
        v = d[k]
        if exclude_none and v is None:
            continue
        parts.append(_quote(k) + ":" + _serialize(v, exclude_none=exclude_none, depth=depth))
    return "{" + ",".join(parts) + "}"


def _utf16_sort_key(s: str) -> tuple[int, ...]:
    """Return *s* as the UTF-16 code unit sequence RFC 8785 §3.2.3 sorts by.

    A supplementary-plane character (code point > U+FFFF) is represented in
    UTF-16 as a surrogate pair starting at 0xD800-0xDBFF, which sorts below
    every BMP character above 0xD800 even though the character's own code
    point sorts above them. Comparing code units instead of code points is
    the only way to reproduce that ordering.
    """
    units: list[int] = []
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            units.append(0xD800 + (cp >> 10))
            units.append(0xDC00 + (cp & 0x3FF))
        else:
            units.append(cp)
    return tuple(units)


def _quote(s: str) -> str:
    """Serialize a Python string as a JSON string per RFC 8785 §3.2.2.2.

    Applies NFC normalization (spec Section 4.3) before escaping. RFC 8785
    defers to ECMAScript JSON.stringify, which escapes only the quote, the
    reverse solidus, and U+0000-U+001F. U+007F, the C1 controls (U+0080-
    U+009F) and the line/paragraph separators (U+2028, U+2029) are emitted
    literally — they are not part of that escape set.
    """
    s = unicodedata.normalize("NFC", s)
    buf: list[str] = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            buf.append('\\"')
        elif ch == "\\":
            buf.append("\\\\")
        elif ch == "\b":
            buf.append("\\b")
        elif ch == "\f":
            buf.append("\\f")
        elif ch == "\n":
            buf.append("\\n")
        elif ch == "\r":
            buf.append("\\r")
        elif ch == "\t":
            buf.append("\\t")
        elif cp <= 0x001F:
            buf.append(f"\\u{cp:04x}")
        else:
            buf.append(ch)
    buf.append('"')
    return "".join(buf)


def _float_to_str(f: float) -> str:
    """Serialize a float per RFC 8785 §3.2.2.3 (ECMAScript Number::toString).

    Implements the ECMA-262 Number::toString algorithm directly rather than
    reformatting Python's `repr`: `repr(f)` already gives the shortest decimal
    digit string that round-trips to *f* (what the spec calls `s`), and
    `Decimal(repr(f)).normalize()` recovers that digit string and its exponent
    without the two shortcuts (integers bounded at 1e15, exponential notation
    switching over at the wrong magnitude) the previous implementation used.

    Raises:
        ValueError: If *f* is NaN or Infinity (not permitted by RFC 8785).
    """
    if math.isnan(f) or math.isinf(f):
        raise ValueError(f"RFC 8785 does not permit NaN or Infinity ({f!r})")
    if f == 0.0:
        return "0"
    sign = "-" if f < 0 else ""
    _, digits, exponent = decimal.Decimal(repr(abs(f))).normalize().as_tuple()
    digit_str = "".join(str(x) for x in digits)
    k = len(digit_str)
    n = exponent + k
    if k <= n <= 21:
        return sign + digit_str + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digit_str[:n] + "." + digit_str[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digit_str
    e = n - 1
    mantissa = digit_str[0] if k == 1 else digit_str[0] + "." + digit_str[1:]
    return sign + mantissa + "e" + ("+" if e >= 0 else "-") + str(abs(e))
