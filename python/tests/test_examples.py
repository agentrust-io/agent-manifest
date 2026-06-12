"""Validate every shipped example manifest against the Pydantic models.

This is the CI drift gate from issue #155: every manifest-shaped JSON file
under examples/ MUST pass ``Manifest.model_validate`` and survive the
verifier's structural stage. A spec/model/example divergence becomes a test
failure instead of silently shipping broken examples.

Supporting (non-manifest) JSON artifacts are explicitly excluded below.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_manifest import Manifest, signing_pre_image
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = REPO_ROOT / "examples"

# JSON files under examples/ that are supporting artifacts, not manifests.
NON_MANIFEST_FILES = {
    "multi-artifact/artifacts/tool-catalog.json",  # bound tool catalog content
    "revocation/revocation-record.json",  # revocation record (spec 3.7)
}

# Every example manifest that existed when this gate was added. Guards the
# discovery glob itself: if these files move without updating this list, the
# test fails loudly instead of silently validating nothing.
KNOWN_MANIFESTS = {
    "level0-software-only.json",
    "level1-tpm-attested.json",
    "delegation-chain/root-manifest.json",
    "delegation-chain/delegate-manifest.json",
    "delegation-chain/sub-delegate-manifest.json",
    "hitl/manifest-with-hitl.json",
    "multi-artifact/manifest.json",
    "revocation/valid-manifest.json",
}


def _discover_manifests() -> list[Path]:
    if not EXAMPLES_DIR.is_dir():
        return []
    return sorted(
        p
        for p in EXAMPLES_DIR.rglob("*.json")
        if p.relative_to(EXAMPLES_DIR).as_posix() not in NON_MANIFEST_FILES
    )


MANIFEST_PATHS = _discover_manifests()

pytestmark = pytest.mark.skipif(
    not EXAMPLES_DIR.is_dir(),
    reason="examples/ directory not present (sdist install?)",
)


def _param_id(path: Path) -> str:
    return path.relative_to(EXAMPLES_DIR).as_posix()


def test_discovery_finds_all_known_manifests() -> None:
    found = {_param_id(p) for p in MANIFEST_PATHS}
    missing = KNOWN_MANIFESTS - found
    assert not missing, f"example manifests missing from discovery: {sorted(missing)}"


@pytest.mark.parametrize("path", MANIFEST_PATHS, ids=_param_id)
def test_example_validates_against_models(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = Manifest.model_validate(data)
    assert str(manifest.manifest_id) == data["manifest_id"]


@pytest.mark.parametrize("path", MANIFEST_PATHS, ids=_param_id)
def test_example_round_trips_through_model_dump(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    manifest = Manifest.model_validate(data)
    dumped = manifest.model_dump(mode="json", by_alias=True, exclude_none=True)
    Manifest.model_validate(dumped)  # must not raise


@pytest.mark.parametrize("path", MANIFEST_PATHS, ids=_param_id)
def test_example_passes_verifier_structural_stage(path: Path) -> None:
    """The verifier must process every example without raising.

    Examples carry placeholder signatures and no trusted keys are supplied,
    so the fail-closed verifier must return UNVERIFIABLE (or EXPIRED once an
    example's expires_at passes) - never VALID, and never an exception.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    result = verify_manifest(data, VerificationContext(), RevocationStore())
    assert result.result in (OverallResult.UNVERIFIABLE, OverallResult.EXPIRED), (
        f"{path.name}: expected fail-closed UNVERIFIABLE/EXPIRED, "
        f"got {result.result.value}"
    )


@pytest.mark.parametrize("path", MANIFEST_PATHS, ids=_param_id)
def test_example_signing_pre_image_is_computable(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    pre_image = signing_pre_image(data)
    assert pre_image  # canonicalization must succeed and be non-empty
