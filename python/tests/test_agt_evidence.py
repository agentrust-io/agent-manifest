"""Tests for scripts/gen_agt_evidence.py and the generated agt-evidence.json."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import importlib.util

_REPO_ROOT = Path(__file__).parent.parent.parent.parent  # agent-manifest root
_SCRIPTS_DIR = _REPO_ROOT / "scripts"

MANIFEST_ARTIFACTS = [
    "identity", "model", "policy", "tools", "data",
    "capabilities", "lineage", "evaluation", "trust_boundary", "delegation",
]


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_agt_evidence", _SCRIPTS_DIR / "gen_agt_evidence.py"
    )
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


@pytest.fixture(scope="module")
def generator():
    return _load_generator()


@pytest.fixture(scope="module")
def evidence(generator) -> dict:
    return generator.generate_evidence()


# --------------------------------------------------------------------------- #
# Schema and top-level structure                                               #
# --------------------------------------------------------------------------- #


def test_schema_field(evidence):
    assert evidence["schema"] == "agt-runtime-evidence/v1"


def test_has_toolkit_version(evidence):
    assert "toolkit_version" in evidence
    assert isinstance(evidence["toolkit_version"], str)


def test_has_deployment_object(evidence):
    assert isinstance(evidence.get("deployment"), dict)


# --------------------------------------------------------------------------- #
# Deployment sub-fields                                                        #
# --------------------------------------------------------------------------- #


def test_policy_files_not_empty(evidence):
    pf = evidence["deployment"]["policy_files_loaded"]
    assert isinstance(pf, list)
    assert len(pf) > 0, "policy_files_loaded must contain at least one entry"


def test_policy_file_paths_exist(evidence):
    """Every reported policy file must exist on disk relative to repo root."""
    for rel in evidence["deployment"]["policy_files_loaded"]:
        full = _REPO_ROOT / rel
        assert full.exists(), f"Policy file missing: {full}"


def test_registered_tools_are_manifest_artifacts(evidence):
    """Registered tools are exactly the 10 manifest artifact types."""
    assert evidence["deployment"]["registered_tools"] == MANIFEST_ARTIFACTS


def test_registered_tools_count(evidence):
    assert len(evidence["deployment"]["registered_tools"]) == 10


def test_audit_sink_enabled(evidence):
    sink = evidence["deployment"]["audit_sink"]
    assert sink.get("enabled") is True
    assert sink.get("target") or sink.get("path") or sink.get("url"), (
        "audit_sink must have a non-empty target, path, or url"
    )


def test_identity_enabled(evidence):
    assert evidence["deployment"]["identity"]["enabled"] is True


def test_identity_type_spiffe(evidence):
    assert evidence["deployment"]["identity"]["type"] == "spiffe"


def test_packages_valid(evidence):
    packages = evidence["deployment"]["packages"]
    assert isinstance(packages, list)
    assert len(packages) > 0
    for pkg in packages:
        assert isinstance(pkg.get("package"), str) and pkg["package"].strip()
        assert isinstance(pkg.get("version"), str) and pkg["version"].strip()


def test_agent_manifest_in_packages(evidence):
    names = [p["package"] for p in evidence["deployment"]["packages"]]
    assert "agent-manifest" in names


# --------------------------------------------------------------------------- #
# main() writes valid JSON                                                     #
# --------------------------------------------------------------------------- #


def test_main_writes_valid_json(tmp_path, generator):
    out = tmp_path / "agt-evidence.json"
    generator.main(str(out))
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "agt-runtime-evidence/v1"
    assert data["generated_at"]  # populated by main()


# --------------------------------------------------------------------------- #
# Governance YAML has deny semantics                                           #
# --------------------------------------------------------------------------- #


def test_governance_yaml_has_deny_by_default():
    """governance/manifest-enforcement.yaml must have deny_by_default: true."""
    import yaml
    gov_path = _REPO_ROOT / "governance" / "manifest-enforcement.yaml"
    data = yaml.safe_load(gov_path.read_text(encoding="utf-8"))
    assert data.get("deny_by_default") is True, (
        "governance/manifest-enforcement.yaml must have deny_by_default: true"
    )


def test_governance_yaml_lists_expected_artifacts():
    """The 10 artifact names in the YAML match our expected list."""
    import yaml
    gov_path = _REPO_ROOT / "governance" / "manifest-enforcement.yaml"
    data = yaml.safe_load(gov_path.read_text(encoding="utf-8"))
    yaml_artifacts = data.get("artifacts", [])
    assert yaml_artifacts == MANIFEST_ARTIFACTS


# --------------------------------------------------------------------------- #
# Integration: GovernanceVerifier.verify_evidence() must pass all checks      #
# --------------------------------------------------------------------------- #


def _try_import_verifier():
    try:
        from agent_compliance.verify import GovernanceVerifier
        return GovernanceVerifier
    except ImportError:
        return None


@pytest.mark.skipif(
    _try_import_verifier() is None,
    reason="agent-governance-toolkit-core not installed",
)
def test_verify_evidence_passes(tmp_path, generator):
    """GovernanceVerifier.verify_evidence() must succeed with no evidence failures."""
    from agent_compliance.verify import GovernanceVerifier

    gov_dir = tmp_path / "governance"
    gov_dir.mkdir()
    shutil.copy(
        _REPO_ROOT / "governance" / "manifest-enforcement.yaml",
        gov_dir / "manifest-enforcement.yaml",
    )

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path, strict=True)

    failures = [c for c in attestation.evidence_checks if c.status == "fail"]
    assert not failures, (
        f"Evidence checks failed:\n"
        + "\n".join(f"  {c.check_id}: {c.message}" for c in failures)
    )


@pytest.mark.skipif(
    _try_import_verifier() is None,
    reason="agent-governance-toolkit-core not installed",
)
def test_verify_evidence_attestation_json(tmp_path, generator):
    """Attestation JSON output has expected structure."""
    from agent_compliance.verify import GovernanceVerifier

    gov_dir = tmp_path / "governance"
    gov_dir.mkdir()
    shutil.copy(
        _REPO_ROOT / "governance" / "manifest-enforcement.yaml",
        gov_dir / "manifest-enforcement.yaml",
    )

    evidence_path = tmp_path / "agt-evidence.json"
    ev = generator.generate_evidence()
    from datetime import datetime, timezone
    ev["generated_at"] = datetime.now(timezone.utc).isoformat()
    evidence_path.write_text(json.dumps(ev, indent=2), encoding="utf-8")

    attestation = GovernanceVerifier().verify_evidence(evidence_path)
    output = json.loads(attestation.to_json())

    assert output["schema"] == "governance-attestation/v1"
    assert output["mode"] == "evidence"
    assert isinstance(output["controls_total"], int)
    assert isinstance(output["attestation_hash"], str)
    assert len(output["attestation_hash"]) == 64
