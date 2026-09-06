from __future__ import annotations

from typing import Any

import agent_manifest._verify as verify_module
from agent_manifest._verify import (
    OverallResult,
    RevocationStore,
    VerificationContext,
    VerificationResult,
    verify_manifest,
)


FUTURE_VERSION = "9.9"
VALID_MANIFEST_ID = "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c"


def _verify(manifest: dict[str, Any]) -> VerificationResult:
    return verify_manifest(manifest, VerificationContext(), RevocationStore())


def test_unsupported_version_preempts_future_only_schema_fields() -> None:
    manifest = {
        "version": FUTURE_VERSION,
        "manifest_id": VALID_MANIFEST_ID,
        "future_only": {"new_profile": ["value"]},
    }

    result = _verify(manifest)

    assert result.result == OverallResult.INCOMPATIBLE_VERSION
    assert result.mismatch_details == []


def test_unsupported_version_preempts_current_schema_failures() -> None:
    manifest = {
        "version": FUTURE_VERSION,
        "manifest_id": 12345,
        "agent_id": ["not", "a", "current", "agent_id"],
        "artifacts": "future-shape",
    }

    result = _verify(manifest)

    assert result.result == OverallResult.INCOMPATIBLE_VERSION
    assert result.mismatch_details == []


def test_missing_version_uses_the_same_incompatible_version_gate() -> None:
    result = _verify({"future_only": True})

    assert result.result == OverallResult.INCOMPATIBLE_VERSION
    assert result.mismatch_details == []


def test_unsupported_version_does_not_invoke_current_schema(monkeypatch) -> None:
    def schema_must_not_run(_manifest: dict[str, Any]) -> list[tuple[str, str]]:
        raise AssertionError("current-version schema ran before version negotiation")

    monkeypatch.setattr(verify_module, "_strict_schema_violations", schema_must_not_run)

    result = _verify({"version": FUTURE_VERSION, "manifest_id": VALID_MANIFEST_ID})

    assert result.result == OverallResult.INCOMPATIBLE_VERSION


def test_unsupported_version_reads_only_the_version_discriminator() -> None:
    class VersionOnlyManifest(dict[str, Any]):
        def get(self, key: str, default: Any = None) -> Any:
            if key != "version":
                raise AssertionError(f"unsupported-version path read {key!r}")
            return super().get(key, default)

    manifest = VersionOnlyManifest(
        version=FUTURE_VERSION,
        manifest_id=VALID_MANIFEST_ID,
        future_only={"shape": "unknown"},
    )

    result = _verify(manifest)

    assert result.result == OverallResult.INCOMPATIBLE_VERSION
    assert result.manifest_id == "unknown"


def test_supported_version_still_applies_current_schema() -> None:
    manifest = {
        "version": "0.1",
        "manifest_id": VALID_MANIFEST_ID,
        "agent_id": "spiffe://trust.example/agent/test",
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "issuer": "spiffe://trust.example/issuer",
        "crypto_profile": "standard",
        "artifacts": {},
        "future_only": True,
    }

    result = _verify(manifest)

    assert result.result == OverallResult.MISMATCH
    assert any(detail.field == "schema:future_only" for detail in result.mismatch_details)
