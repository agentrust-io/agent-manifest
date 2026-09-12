"""Regression tests for the custom scalar validators in ``_types.py``.

Covers a specific Python regex gotcha: ``$`` matches at end-of-string OR
just before a single trailing ``'\n'``. A validator built as
``re.compile(r"^...$").match(v)`` would therefore accept
``"<valid-value>\n"`` as if it were the unmodified, valid value. These
validators must use ``.fullmatch()`` (which has no such exception) so a
trailing newline is rejected like any other malformed suffix.
"""

import pytest

from agent_manifest._types import HashValue, ManifestId

GOOD_MANIFEST_ID = "01890a5d-ac96-774b-bcce-b302099a8057"
GOOD_HASH = "sha256:" + "a" * 64


def test_manifest_id_accepts_well_formed_value():
    assert ManifestId._validate(GOOD_MANIFEST_ID) == GOOD_MANIFEST_ID


def test_manifest_id_rejects_trailing_newline():
    with pytest.raises(ValueError, match="not a valid UUID v7"):
        ManifestId._validate(GOOD_MANIFEST_ID + "\n")


def test_manifest_id_rejects_illegal_prefix_and_suffix():
    with pytest.raises(ValueError, match="not a valid UUID v7"):
        ManifestId._validate("!!!!" + GOOD_MANIFEST_ID)
    with pytest.raises(ValueError, match="not a valid UUID v7"):
        ManifestId._validate(GOOD_MANIFEST_ID + "!!!!")


def test_hash_value_accepts_well_formed_value():
    assert HashValue._validate(GOOD_HASH) == GOOD_HASH


def test_hash_value_rejects_trailing_newline():
    with pytest.raises(ValueError, match="Invalid hash value"):
        HashValue._validate(GOOD_HASH + "\n")


def test_hash_value_rejects_illegal_prefix_and_suffix():
    with pytest.raises(ValueError, match="Invalid hash value"):
        HashValue._validate("!!!!" + GOOD_HASH)
    with pytest.raises(ValueError, match="Invalid hash value"):
        HashValue._validate(GOOD_HASH + "!!!!")


def test_manifest_id_json_schema_pattern_still_anchored():
    # The exported JSON-schema pattern is consumed by non-Python tools
    # following JSON Schema/ECMA 262 semantics, where a `pattern` without
    # `^`/`$` anchors means "contains a match" rather than "matches
    # exactly". The anchors must stay in the exported string even though
    # internal validation now uses `.fullmatch()` instead of relying on
    # them.
    assert ManifestId._PATTERN.pattern.startswith("^")
    assert ManifestId._PATTERN.pattern.endswith("$")


def test_hash_value_json_schema_pattern_still_anchored():
    assert HashValue._PATTERN.pattern.startswith("^")
    assert HashValue._PATTERN.pattern.endswith("$")
