"""Agent Plugins bundle adapter - issue #282."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from agent_manifest import (
    DataClassification,
    PluginBundleError,
    PLUGIN_MANIFEST_EXTENSION,
    PluginReferenceStatus,
    bundle_digest,
    bundle_reference_digest,
    load_plugin_bundle,
    plugin_manifest_reference,
    system_prompt_binding_from_bundle,
    verify_plugin_manifest_reference,
)
from agent_manifest._signing import Ed25519Signer, generate_ed25519
from agent_manifest._verify import RevocationStore, VerificationContext

SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"


def _bundle(tmp_path, *, name="demo", version="1.2.0", skills=None, mcp=None, extra=None):
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    manifest = {"$schema": SCHEMA, "name": name}
    if version is not None:
        manifest["version"] = version
    if extra:
        manifest.update(extra)
    (root / "plugin.json").write_text(json.dumps(manifest), encoding="utf-8")

    for skill_name, text in (skills or {"greeter": "# Greeter\nBe nice.\n"}).items():
        d = root / "skills" / skill_name
        d.mkdir(parents=True)
        (d / "SKILL.md").write_text(text, encoding="utf-8")

    if mcp is not None:
        (root / "mcp.json").write_text(json.dumps(mcp), encoding="utf-8")
    return root


def test_loads_a_minimal_bundle(tmp_path):
    bundle = load_plugin_bundle(_bundle(tmp_path))
    assert bundle.name == "demo"
    assert bundle.version == "1.2.0"
    assert bundle.digest.startswith("sha256:")
    assert [s.name for s in bundle.skills] == ["greeter"]
    assert bundle.declared_mcp_servers == ()
    assert bundle.has_resolvable_tools is False


def test_mcp_json_is_optional(tmp_path):
    """A bundle of skills alone is legal in 1.0.0 and must not fail."""
    assert load_plugin_bundle(_bundle(tmp_path)).declared_mcp_servers == ()


def test_declared_servers_are_recorded_as_declarations(tmp_path):
    root = _bundle(tmp_path, mcp={"mcpServers": {"files": {"command": "srv", "args": ["--ro"]}}})
    bundle = load_plugin_bundle(root)
    assert bundle.has_resolvable_tools is True
    assert [s.name for s in bundle.declared_mcp_servers] == ["files"]
    assert bundle.declared_mcp_servers[0].declaration_hash.startswith("sha256:")


def test_bare_server_mapping_is_accepted(tmp_path):
    """Both mcp.json shapes appear in the wild; rejecting one fails real bundles."""
    root = _bundle(tmp_path, mcp={"files": {"command": "srv"}})
    assert [s.name for s in load_plugin_bundle(root).declared_mcp_servers] == ["files"]


def test_changing_a_server_declaration_changes_its_hash(tmp_path):
    a = load_plugin_bundle(_bundle(tmp_path / "a", mcp={"mcpServers": {"f": {"command": "x"}}}))
    b = load_plugin_bundle(_bundle(tmp_path / "b", mcp={"mcpServers": {"f": {"command": "y"}}}))
    assert a.declared_mcp_servers[0].declaration_hash != b.declared_mcp_servers[0].declaration_hash


def test_unknown_schema_is_refused(tmp_path):
    root = _bundle(tmp_path, extra={"$schema": "https://example.invalid/other.json"})
    with pytest.raises(PluginBundleError, match="unsupported plugin.json"):
        load_plugin_bundle(root)


def test_missing_schema_is_refused(tmp_path):
    root = tmp_path / "x"
    root.mkdir()
    (root / "plugin.json").write_text(json.dumps({"name": "x"}), encoding="utf-8")
    with pytest.raises(PluginBundleError, match="unsupported plugin.json"):
        load_plugin_bundle(root)


def test_missing_plugin_json_is_refused(tmp_path):
    root = tmp_path / "x"
    root.mkdir()
    (root / "README.md").write_text("hi", encoding="utf-8")
    with pytest.raises(PluginBundleError, match="plugin.json not found"):
        load_plugin_bundle(root)


def test_malformed_plugin_json_is_refused(tmp_path):
    root = tmp_path / "x"
    root.mkdir()
    (root / "plugin.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(PluginBundleError, match="not valid JSON"):
        load_plugin_bundle(root)


def test_not_a_directory_is_refused(tmp_path):
    with pytest.raises(PluginBundleError, match="not a directory"):
        load_plugin_bundle(tmp_path / "nope")


# --- the digest -----------------------------------------------------------


def test_digest_is_stable_for_identical_content(tmp_path):
    a = _bundle(tmp_path / "a")
    b = _bundle(tmp_path / "b")
    assert bundle_digest(a) == bundle_digest(b)


def test_digest_covers_files_the_adapter_does_not_parse(tmp_path):
    """Unmeasured must not be indistinguishable from empty.

    A client extension directory is not something this adapter understands. If
    the digest skipped it, two bundles differing only there would report the
    same digest, which is the failure this construction exists to prevent.
    """
    root = _bundle(tmp_path)
    before = bundle_digest(root)
    ext = root / "com.example.client" / "hooks"
    ext.mkdir(parents=True)
    (ext / "on-install.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    assert bundle_digest(root) != before


def test_digest_binds_the_path_not_just_the_content(tmp_path):
    """A rename with identical bytes is a different bundle."""
    root = _bundle(tmp_path)
    before = bundle_digest(root)
    src = root / "skills" / "greeter" / "SKILL.md"
    dst = root / "skills" / "greeter"
    (dst / "RENAMED.md").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    src.unlink()
    assert bundle_digest(root) != before


def test_empty_directory_is_refused(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    with pytest.raises(PluginBundleError, match="empty"):
        bundle_digest(root)


# --- the boundary ---------------------------------------------------------


def test_adapter_exposes_no_tool_manifest_builder():
    """The boundary, asserted.

    ToolEntry requires schema_hash and description_hash per tool. mcp.json
    declares servers and carries neither. Any function here that produced a
    ToolManifestBinding from a bundle would be inventing both, so there is
    deliberately no such function and this test fails if one appears.
    """
    import agent_manifest._plugins as plugins

    offenders = [
        name
        for name in dir(plugins)
        if "tool" in name.lower() and not name.startswith("_")
    ]
    assert offenders == [], (
        f"{offenders} looks like a tool-manifest builder. A bundle cannot "
        "supply per-tool schema and description hashes; resolve the servers "
        "instead. See spec section 6.5."
    )


# --- system prompt binding ------------------------------------------------


def test_system_prompt_binding_from_skills(tmp_path):
    bundle = load_plugin_bundle(_bundle(tmp_path))
    binding = system_prompt_binding_from_bundle(
        bundle, classification=DataClassification.internal
    )
    assert binding.hash.startswith("sha256:")
    assert binding.version == "1.2.0"


def test_binding_changes_when_skill_text_changes(tmp_path):
    a = load_plugin_bundle(_bundle(tmp_path / "a", skills={"g": "one\n"}))
    b = load_plugin_bundle(_bundle(tmp_path / "b", skills={"g": "two\n"}))
    ha = system_prompt_binding_from_bundle(a, classification=DataClassification.internal).hash
    hb = system_prompt_binding_from_bundle(b, classification=DataClassification.internal).hash
    assert ha != hb


def test_binding_binds_skill_path_so_split_skills_differ(tmp_path):
    """Same text, different skill layout, different hash."""
    one = load_plugin_bundle(_bundle(tmp_path / "one", skills={"a": "x\ny\n"}))
    two = load_plugin_bundle(_bundle(tmp_path / "two", skills={"a": "x\n", "b": "y\n"}))
    h1 = system_prompt_binding_from_bundle(one, classification=DataClassification.internal).hash
    h2 = system_prompt_binding_from_bundle(two, classification=DataClassification.internal).hash
    assert h1 != h2


def test_binding_requires_skills(tmp_path):
    root = tmp_path / "noskills"
    root.mkdir()
    (root / "plugin.json").write_text(
        json.dumps({"$schema": SCHEMA, "name": "noskills", "version": "1"}), encoding="utf-8"
    )
    bundle = load_plugin_bundle(root)
    with pytest.raises(PluginBundleError, match="no skills"):
        system_prompt_binding_from_bundle(bundle, classification=DataClassification.internal)


def test_binding_requires_a_version_somewhere(tmp_path):
    """version is optional in plugin.json and required by SystemPromptBinding."""
    bundle = load_plugin_bundle(_bundle(tmp_path, version=None))
    with pytest.raises(PluginBundleError, match="no 'version'"):
        system_prompt_binding_from_bundle(bundle, classification=DataClassification.internal)

    binding = system_prompt_binding_from_bundle(
        bundle, classification=DataClassification.internal, version="0.0.1"
    )
    assert binding.version == "0.0.1"


# --- signed manifest reference --------------------------------------------


def _referenced_manifest(root, key):
    now = datetime.now(timezone.utc)
    manifest = {
        "manifest_id": "018f4a3b-2c1d-7e5f-a8b9-0d1e2f3a4b5c",
        "agent_id": "spiffe://trust.example/plugin/demo",
        "version": "0.1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "issuer": "spiffe://trust.example/issuer/ci",
        "crypto_profile": "standard",
        "source_bundle": {
            "format": "agent-plugins-1.0.0",
            "digest": bundle_reference_digest(root),
        },
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "policy_bundle": {"hash": "sha256:" + "b" * 64},
            "model_identity": {
                "model_hash": None,
                "version": "chosen-at-runtime",
                "deployment_type": "api",
            },
        },
    }
    manifest["signature"] = Ed25519Signer(key).sign(manifest)
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def _attach_reference(root, manifest_bytes, *, uri="https://registry.example/manifest.json"):
    plugin_path = root / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin.setdefault("extensions", {})[PLUGIN_MANIFEST_EXTENSION] = {
        "manifest_uri": uri,
        "manifest_digest": "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
    }
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")


def test_reference_digest_excludes_only_its_own_namespace(tmp_path):
    root = _bundle(tmp_path)
    before = bundle_reference_digest(root)
    _attach_reference(root, b"manifest")
    assert bundle_reference_digest(root) == before

    plugin_path = root / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["extensions"]["com.example.other"] = {"setting": True}
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    assert bundle_reference_digest(root) != before


def test_absent_reference_is_not_a_failure_and_does_not_fetch(tmp_path):
    root = _bundle(tmp_path)

    def should_not_fetch(_uri):
        raise AssertionError("fetch called for absent reference")

    result = verify_plugin_manifest_reference(
        root,
        fetch=should_not_fetch,
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.NOT_PRESENT


def test_reference_parses_the_controlled_namespace(tmp_path):
    root = _bundle(tmp_path)
    _attach_reference(root, b"manifest")
    reference = plugin_manifest_reference(load_plugin_bundle(root))
    assert reference is not None
    assert reference.manifest_uri == "https://registry.example/manifest.json"


def test_reference_rejects_unknown_members(tmp_path):
    root = _bundle(tmp_path)
    _attach_reference(root, b"manifest")
    plugin_path = root / "plugin.json"
    plugin = json.loads(plugin_path.read_text(encoding="utf-8"))
    plugin["extensions"][PLUGIN_MANIFEST_EXTENSION]["trusted_key"] = "attacker-key"
    plugin_path.write_text(json.dumps(plugin), encoding="utf-8")
    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: b"manifest",
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.INVALID


@pytest.mark.parametrize(
    "uri",
    [
        "http://registry.example/manifest.json",
        "https://user:password@registry.example/manifest.json",
        "https://registry.example/manifest.json#unsigned-fragment",
    ],
)
def test_unsafe_manifest_locations_are_invalid(tmp_path, uri):
    root = _bundle(tmp_path)
    _attach_reference(root, b"manifest", uri=uri)
    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: b"manifest",
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.INVALID


def test_resolved_reference_verifies_manifest_and_bundle(tmp_path):
    root = _bundle(tmp_path)
    key = generate_ed25519()
    manifest_bytes = _referenced_manifest(root, key)
    _attach_reference(root, manifest_bytes)

    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: manifest_bytes,
        context=VerificationContext(trusted_keys={key.key_id: key.public_b64url()}),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.VERIFIED
    assert result.manifest_result.signature_verified is True


def test_json_reference_allows_leading_whitespace_without_changing_raw_digest(tmp_path):
    root = _bundle(tmp_path)
    key = generate_ed25519()
    manifest_bytes = b" \r\n" + _referenced_manifest(root, key)
    _attach_reference(root, manifest_bytes)
    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: manifest_bytes,
        context=VerificationContext(trusted_keys={key.key_id: key.public_b64url()}),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.VERIFIED


def test_oversized_fetched_manifest_is_rejected_before_parsing(tmp_path):
    root = _bundle(tmp_path)
    oversized = b"{" + b" " * (16 * 1024 * 1024)
    _attach_reference(root, oversized)
    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: oversized,
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.INVALID
    assert "exceeds" in result.reason


def test_unreachable_reference_is_distinct_from_mismatch(tmp_path):
    root = _bundle(tmp_path)
    _attach_reference(root, b"manifest")

    def unavailable(_uri):
        raise TimeoutError("timed out")

    result = verify_plugin_manifest_reference(
        root,
        fetch=unavailable,
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.UNRESOLVABLE


def test_fetched_manifest_digest_mismatch_is_fatal(tmp_path):
    root = _bundle(tmp_path)
    _attach_reference(root, b"expected")
    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: b"substituted",
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.MISMATCH


def test_bundle_changed_after_manifest_was_signed_is_fatal(tmp_path):
    root = _bundle(tmp_path)
    key = generate_ed25519()
    manifest_bytes = _referenced_manifest(root, key)
    _attach_reference(root, manifest_bytes)
    (root / "skills" / "greeter" / "SKILL.md").write_text("poisoned\n", encoding="utf-8")

    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: manifest_bytes,
        context=VerificationContext(trusted_keys={key.key_id: key.public_b64url()}),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.MISMATCH


def test_reference_does_not_bootstrap_its_own_trust_key(tmp_path):
    root = _bundle(tmp_path)
    key = generate_ed25519()
    manifest_bytes = _referenced_manifest(root, key)
    _attach_reference(root, manifest_bytes)
    result = verify_plugin_manifest_reference(
        root,
        fetch=lambda _uri: manifest_bytes,
        context=VerificationContext(),
        revocation_store=RevocationStore(),
    )
    assert result.status == PluginReferenceStatus.UNVERIFIABLE
