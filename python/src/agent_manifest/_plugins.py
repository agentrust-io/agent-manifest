"""Agent Plugins bundle adapter - issue #282.

Reads an `Agent Plugins 1.0.0 <https://agent-plugins.org>`_ bundle and produces
the manifest inputs it can legitimately produce. Spec section 6.5 states the
boundary this module implements: Agent Plugins describes what a client should
install, a manifest describes what actually ran, and a bundle is an input to a
manifest rather than an alternative to one.

What this module deliberately does **not** do is build a
:class:`~agent_manifest.models.ToolManifestBinding`. That is not an omission to
be filled in later, it is the boundary being enforced by the data model:
:class:`~agent_manifest.models.ToolEntry` requires a ``schema_hash`` and a
``description_hash`` for every tool, and ``mcp.json`` declares which servers to
start without enumerating the tools those servers expose. A bundle carries
neither hash and cannot be made to. Producing a tool manifest from a bundle
alone would mean inventing the two values that the artifact exists to bind, so
:func:`load_plugin_bundle` records the server declarations as declarations and
stops there. Resolving them requires starting the servers and asking, which is
a runtime concern and not this module's job.

The digest is taken over the whole directory, including files this module does
not understand, such as the reverse-domain client extension directories the
format permits. A digest that covered only the parts we parse would report the
same value for two bundles that differ in a file we chose not to read, which is
the failure mode where unmeasured is indistinguishable from empty.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ._merkle import CorpusDocument, build_corpus_tree

__all__ = [
    "PluginBundleError",
    "PluginSkill",
    "DeclaredMcpServer",
    "PluginBundle",
    "load_plugin_bundle",
    "bundle_digest",
    "system_prompt_binding_from_bundle",
    "SUPPORTED_PLUGIN_SCHEMAS",
]

# The 1.0.0 schema pins `$schema` to exactly this value via a JSON Schema
# `const`, so an unrecognised value is a different format and not a newer
# revision of this one. Fail closed rather than guess.
SUPPORTED_PLUGIN_SCHEMAS = frozenset(
    {"https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"}
)

# DOS: a bundle is untrusted input. These bound what a malformed or hostile
# directory can cost before it is rejected.
_MAX_BUNDLE_FILES = 10_000
_MAX_BUNDLE_BYTES = 256 * 1024 * 1024


class PluginBundleError(ValueError):
    """A directory is not a usable Agent Plugins 1.0.0 bundle."""


@dataclass(frozen=True)
class PluginSkill:
    """One skill in the bundle.

    ``content_hash`` covers ``SKILL.md`` only. A skill directory may also carry
    ``scripts/`` and ``references/``, which are covered by the bundle digest but
    not by this field, because the system prompt artifact binds instruction text
    rather than the executables shipped alongside it.
    """

    name: str
    relative_path: str
    content_hash: str


@dataclass(frozen=True)
class DeclaredMcpServer:
    """One server declared in ``mcp.json``.

    A declaration, not a resolution. ``declaration_hash`` binds what the bundle
    said so a later resolution can be compared against it; it says nothing about
    the tools the server actually exposed when it started.
    """

    name: str
    declaration_hash: str
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class PluginBundle:
    """A parsed Agent Plugins 1.0.0 bundle."""

    path: Path
    name: str
    schema: str
    version: Optional[str]
    digest: str
    skills: tuple[PluginSkill, ...]
    declared_mcp_servers: tuple[DeclaredMcpServer, ...]
    extensions: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def has_resolvable_tools(self) -> bool:
        """True when the bundle declares servers whose tools need resolving.

        A caller that wants a tool manifest must resolve these itself. See the
        module docstring for why this module will not do it from the bundle.
        """
        return bool(self.declared_mcp_servers)


def _hash_bytes(data: bytes) -> str:
    import hashlib

    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def bundle_digest(path: Path) -> str:
    """Digest every file under *path*, returning a ``HashValue``.

    Leaves are ``relative_posix_path || 0x00 || file_bytes`` fed through the
    same Merkle construction the RAG corpus artifact uses, so the path is bound
    as well as the content and a rename is a different digest.

    Every regular file is included. Nothing is skipped for being unrecognised,
    because a digest that skips what it does not understand cannot distinguish
    a bundle with an extra file from one without it.
    """
    documents: list[CorpusDocument] = []
    total_bytes = 0

    for entry in sorted(p for p in path.rglob("*") if p.is_file()):
        if len(documents) >= _MAX_BUNDLE_FILES:
            raise PluginBundleError(
                f"bundle contains more than {_MAX_BUNDLE_FILES} files: {path}"
            )
        data = entry.read_bytes()
        total_bytes += len(data)
        if total_bytes > _MAX_BUNDLE_BYTES:
            raise PluginBundleError(
                f"bundle exceeds {_MAX_BUNDLE_BYTES} bytes: {path}"
            )
        relative = entry.relative_to(path).as_posix()
        documents.append(CorpusDocument(document_id=relative, content_bytes=data))

    if not documents:
        raise PluginBundleError(f"bundle directory is empty: {path}")

    return build_corpus_tree(documents)


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise PluginBundleError(f"{label} not found: {path}") from None
    except UnicodeDecodeError as exc:
        raise PluginBundleError(f"{label} is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PluginBundleError(f"{label} is not valid JSON: {path}: {exc}") from exc


def _read_skills(root: Path) -> tuple[PluginSkill, ...]:
    skills_dir = root / "skills"
    if not skills_dir.is_dir():
        return ()

    skills: list[PluginSkill] = []
    for child in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        skill_md = child / "SKILL.md"
        if not skill_md.is_file():
            # A directory under skills/ with no SKILL.md is not a skill. It is
            # still covered by the bundle digest, so ignoring it here loses
            # nothing a verifier needs.
            continue
        skills.append(
            PluginSkill(
                name=child.name,
                relative_path=skill_md.relative_to(root).as_posix(),
                content_hash=_hash_bytes(skill_md.read_bytes()),
            )
        )
    return tuple(skills)


def _read_mcp_servers(root: Path) -> tuple[DeclaredMcpServer, ...]:
    mcp_path = root / "mcp.json"
    if not mcp_path.is_file():
        # mcp.json is optional in 1.0.0. A bundle of skills alone is valid.
        return ()

    raw = _load_json(mcp_path, "mcp.json")
    if not isinstance(raw, dict):
        raise PluginBundleError(f"mcp.json must be a JSON object: {mcp_path}")

    # 1.0.0 nests declarations under mcpServers. Accept a bare mapping too,
    # because the surrounding ecosystem writes both and rejecting the second
    # would fail a bundle that every client accepts.
    servers = raw.get("mcpServers", raw)
    if not isinstance(servers, dict):
        raise PluginBundleError(f"mcp.json mcpServers must be an object: {mcp_path}")

    declared: list[DeclaredMcpServer] = []
    for name in sorted(servers):
        declaration = servers[name]
        canonical = json.dumps(
            {name: declaration}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        declared.append(
            DeclaredMcpServer(
                name=name,
                declaration_hash=_hash_bytes(canonical),
                raw=declaration if isinstance(declaration, dict) else {},
            )
        )
    return tuple(declared)


def load_plugin_bundle(path: Path | str) -> PluginBundle:
    """Read the Agent Plugins bundle at *path*.

    Raises:
        PluginBundleError: the directory is missing, is not a directory, has no
            ``plugin.json``, carries a ``$schema`` this version does not
            recognise, or is malformed.
    """
    root = Path(path)
    if not root.is_dir():
        raise PluginBundleError(f"not a directory: {root}")

    manifest = _load_json(root / "plugin.json", "plugin.json")
    if not isinstance(manifest, dict):
        raise PluginBundleError(f"plugin.json must be a JSON object: {root}")

    schema = manifest.get("$schema")
    if schema not in SUPPORTED_PLUGIN_SCHEMAS:
        raise PluginBundleError(
            f"unsupported plugin.json $schema {schema!r}. This adapter reads "
            f"{', '.join(sorted(SUPPORTED_PLUGIN_SCHEMAS))}. Refusing rather "
            "than guessing at an unknown format."
        )

    name = manifest.get("name")
    if not isinstance(name, str) or not name:
        raise PluginBundleError(f"plugin.json has no usable 'name': {root}")

    version = manifest.get("version")
    if version is not None and not isinstance(version, str):
        raise PluginBundleError(f"plugin.json 'version' must be a string: {root}")

    extensions = manifest.get("extensions")
    if extensions is not None and not isinstance(extensions, dict):
        raise PluginBundleError(f"plugin.json 'extensions' must be an object: {root}")

    return PluginBundle(
        path=root,
        name=name,
        schema=schema,
        version=version,
        digest=bundle_digest(root),
        skills=_read_skills(root),
        declared_mcp_servers=_read_mcp_servers(root),
        extensions=extensions or {},
    )


def system_prompt_binding_from_bundle(
    bundle: PluginBundle,
    *,
    classification: Any,
    version: Optional[str] = None,
    bound_at: Optional[datetime] = None,
    language: Optional[str] = None,
) -> Any:
    """Build a :class:`SystemPromptBinding` from the bundle's skills.

    The hash covers every ``SKILL.md`` in the bundle, joined through the same
    Merkle construction as the bundle digest so the skill's path is bound
    alongside its text. One skill and five skills therefore produce different
    values even when the concatenated text would match.

    ``version`` defaults to the bundle's ``version``. Agent Plugins leaves that
    field an unconstrained string, so it is carried through as written and is
    not parsed or compared as a version number.

    Raises:
        PluginBundleError: the bundle declares no skills, so there is no
            instruction material to bind.
    """
    from ._types import HashValue
    from .models import SystemPromptBinding

    if not bundle.skills:
        raise PluginBundleError(
            f"bundle {bundle.name!r} declares no skills, so it carries no "
            "system prompt material to bind"
        )

    documents = [
        CorpusDocument(
            document_id=skill.relative_path,
            content_bytes=(bundle.path / skill.relative_path).read_bytes(),
        )
        for skill in bundle.skills
    ]

    resolved_version = version or bundle.version
    if not resolved_version:
        raise PluginBundleError(
            f"bundle {bundle.name!r} has no 'version' in plugin.json, which is "
            "optional there and required by SystemPromptBinding. Pass version= "
            "explicitly."
        )

    return SystemPromptBinding(
        hash=HashValue(build_corpus_tree(documents)),
        version=resolved_version,
        classification=classification,
        language=language,
        bound_at=bound_at or datetime.now(timezone.utc),
    )
