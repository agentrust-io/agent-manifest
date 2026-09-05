"""Agent Manifest CLI — issue #15.

Commands:
  manifest create   Build a draft manifest from a config file
  manifest sign     Sign a draft manifest with Ed25519 (or hybrid)
  manifest attest   Extend manifest hash into hardware + append attestation block
  manifest verify   Call the verification endpoint and print the result
  manifest revoke   Publish a revocation record

All commands write JSON to stdout and accept --output/-o to write to a file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, cast

try:
    import click
except ImportError:
    raise ImportError(
        "CLI requires click. Install with: pip install 'agent-manifest[cli]'"
    )

from ._auto_provider import select_provider
from ._cose import COSE_MANIFEST_VERSION
from ._providers import AttestationUnavailableError
from ._revocation import CRLIntegrityError, FileCRL
from ._signing import Ed25519Signer, ed25519_from_private_bytes, generate_ed25519
from ._types import ManifestId
from ._verify import (
    HitlResult,
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)


def _load_json(path: str) -> dict[str, Any]:
    with open(path) as f:
        return cast(dict[str, Any], json.load(f))


def _load_manifest_or_envelope(path: str) -> "dict[str, Any] | bytes":
    """Return a v0.1 manifest dict, or the bytes of a v0.2 COSE envelope.

    The envelope is detected from the CBOR tag that opens the file, not from
    the file extension. A manifest carries its own type, and guessing a format
    from a filename is the ambiguity the media-type rules exist to remove
    (envelope spec section 7).
    """
    raw = Path(path).read_bytes()
    # d2 = tag(18) COSE_Sign1, d8 62 = tag(98) COSE_Sign. Neither can begin a
    # JSON document, so this is a decision, not a guess.
    if raw[:1] == b"\xd2" or raw[:2] == b"\xd8\x62":
        return raw
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise click.ClickException(f"{path} is neither JSON nor a COSE envelope: {exc}")
    if not isinstance(data, dict):
        raise click.ClickException(f"{path} does not contain a manifest object.")
    return data


def _write(data: dict[str, Any], output: Optional[str]) -> None:
    text = json.dumps(data, indent=2, default=str)
    if output:
        # INJ-001: resolve path and prevent writing to unexpected locations
        out_path = Path(output).resolve()
        # Warn if writing outside cwd — but don't block; callers may need arbitrary paths
        out_path.write_text(text)
        click.echo(f"Written to {output}", err=True)
    else:
        click.echo(text)


def _public_bytes_from_hex_file(path: str, label: str = "Public key") -> bytes:
    """Load and validate a raw Ed25519 public key from a hex file."""
    key_path = Path(path).resolve()
    if not key_path.is_file():
        raise click.ClickException(
            f"{label} file not found or is not a regular file: {path}"
        )

    key_hex = key_path.read_text().strip()
    try:
        public_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise click.ClickException(f"{label} file does not contain valid hex data.")

    if len(public_bytes) != 32:
        raise click.ClickException(
            f"Ed25519 public key must be 32 bytes, got {len(public_bytes)} bytes."
        )

    return public_bytes


def _trusted_key_from_public_hex(path: str) -> dict[str, str]:
    """Load a raw Ed25519 public key hex file as verifier trusted_keys."""
    public_bytes = _public_bytes_from_hex_file(path)
    key_id = hashlib.sha256(public_bytes).hexdigest()
    public_b64 = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()
    return {key_id: public_b64}


def _approver_public_keys(specs: tuple[str, ...]) -> dict[str, str]:
    """Parse ``APPROVER_ID=PATH`` pairs into verifier approver_public_keys.

    HITL approvals attach outside the manifest signature, so the relying party
    supplies the approver keys it trusts. Without them an approval is
    UNVERIFIABLE and can never reach VALID.
    """
    keys: dict[str, str] = {}
    for spec in specs:
        approver_id, separator, path = spec.partition("=")
        if not separator or not approver_id or not path:
            raise click.ClickException(
                "--approver-key expects APPROVER_ID=PATH, got: " + spec
            )
        if approver_id in keys:
            raise click.ClickException(
                f"--approver-key given more than once for approver_id {approver_id}"
            )
        public_bytes = _public_bytes_from_hex_file(path, "Approver key")
        keys[approver_id] = (
            base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()
        )
    return keys


@click.group()
@click.version_option(package_name="agent-manifest")
def cli() -> None:
    """Agent Manifest SDK CLI."""


def _make_uuid7() -> str:
    """Generate a UUID v7 (time-ordered) per RFC 9562."""
    import time
    # 48-bit millisecond timestamp
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF
    # 74 random bits from os.urandom — not cryptographic use, just uniqueness
    rand_int = int.from_bytes(os.urandom(10), "big")
    rand_a = (rand_int >> 62) & 0xFFF       # 12 bits for rand_a
    rand_b = rand_int & 0x3FFFFFFFFFFFFFFF  # 62 bits for rand_b
    # Pack: ts_ms(48) | 0x7(4) | rand_a(12) | 0b10(2) | rand_b(62)
    hi = (ts_ms << 16) | (0x7 << 12) | rand_a
    lo = (0b10 << 62) | rand_b
    hex_str = f"{hi:016x}{lo:016x}"
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


@cli.command("create")
@click.argument("config", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def create(config: str, output: Optional[str]) -> None:
    """Create a draft manifest from a JSON config file.

    CONFIG must be a JSON file with at minimum: agent_id, issuer,
    issued_at, expires_at, and an artifacts block.

    
    Example:
      manifest create config.json -o draft.json
    """
    data = _load_json(config)

    # Assign a UUID v7 manifest ID if not provided (CRYPTO-009)
    if "manifest_id" not in data:
        data["manifest_id"] = _make_uuid7()

    data.setdefault("version", "0.1")
    data.setdefault("crypto_profile", "standard")

    click.echo(f"Created draft manifest {data.get('manifest_id')}", err=True)
    _write(data, output)


@cli.command("sign")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--key", "-k", required=True, help="Path to raw 32-byte Ed25519 private key (hex file)")
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def sign(manifest_file: str, key: str, output: Optional[str]) -> None:
    """Sign a draft manifest with Ed25519.

    KEY must be a file containing the 64-hex-character (32-byte) Ed25519
    private key seed.

    
    Example:
      manifest sign draft.json --key private.hex -o signed.json
    """
    data = _load_json(manifest_file)

    # INJ-002: validate key path is a regular file before reading
    key_path = Path(key).resolve()
    if not key_path.is_file():
        raise click.ClickException(f"Key file not found or is not a regular file: {key}")

    key_hex = key_path.read_text().strip()
    # SEC-010: wrap hex decode so ValueError doesn't expose key_hex in traceback
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        raise click.ClickException("Key file does not contain valid hex data.")
    finally:
        del key_hex  # prevent key material from lingering in locals

    kp = ed25519_from_private_bytes(key_bytes)

    # The envelope follows the manifest version, never a flag (ADR-0011). A
    # 0.2 manifest is signed as COSE and written as binary CBOR; a 0.1
    # manifest gets the detached signature block exactly as before.
    if data.get("version") == COSE_MANIFEST_VERSION:
        from ._cose import sign_cose_sign1

        envelope = sign_cose_sign1(data, kp)
        click.echo(
            f"Signed with key_id={kp.key_id} (COSE_Sign1, manifest version "
            f"{COSE_MANIFEST_VERSION})",
            err=True,
        )
        if output is None:
            raise click.ClickException(
                "A COSE envelope is binary CBOR. Use --output to write it to a "
                "file rather than to the terminal."
            )
        Path(output).write_bytes(envelope)
        return

    signer = Ed25519Signer(kp)
    sig_block = signer.sign(data)
    sig_block["signed_at"] = datetime.now(timezone.utc).isoformat()
    data["signature"] = sig_block

    click.echo(f"Signed with key_id={sig_block['key_id']}", err=True)
    _write(data, output)


@cli.command("keygen")
@click.option("--output-dir", "-d", default=".", help="Directory to write key files")
def keygen(output_dir: str) -> None:
    """Generate a new Ed25519 key pair for manifest signing.

    \b
    Writes:
      private.hex - 64-hex private key seed (keep secret, mode 0600)
      public.hex  - 64-hex public key bytes

    
    Example:
      manifest keygen -d ./keys/
    """
    kp = generate_ed25519()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    pub_hex = kp.public_bytes.hex()
    priv_raw = kp.private_key.private_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
    ).hex()

    private_path = out / "private.hex"
    public_path = out / "public.hex"

    # CRYPTO-008/SEC-005: write private key with restrictive permissions (0600)
    private_path.write_text(priv_raw)
    os.chmod(private_path, 0o600)
    public_path.write_text(pub_hex)

    # Send success messages to stderr so stdout is clean for scripting
    click.echo(f"Generated key pair in {out}/", err=True)
    click.echo(f"  key_id = {kp.key_id}", err=True)
    click.echo(f"  public = {pub_hex[:16]}...{pub_hex[-8:]}", err=True)
    click.echo("Keep private.hex secret.", err=True)


@cli.command("attest")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--provider", "-p", default="auto",
              type=click.Choice(["auto", "azure-cvm", "tpm", "sev-snp", "tdx", "opaque", "software"]),
              help="Attestation provider (default: auto)")
@click.option("--level", default=0, type=int, help="Minimum conformance level (0-3)")
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def attest(manifest_file: str, provider: str, level: int, output: Optional[str]) -> None:
    """Extend the manifest hash into hardware and append the attestation block.

    For TPM: requires tpm2-tools (apt-get install tpm2-tools).
    For swtpm in CI: set TPM2TOOLS_TCTI=swtpm: before running.

    
    Example:
      manifest attest signed.json --provider tpm --level 1 -o attested.json
    """
    data = _load_json(manifest_file)
    try:
        if provider == "auto":
            prov = select_provider(level=level)
        elif provider == "azure-cvm":
            from ._hw_providers import AzureCVMProvider
            prov = AzureCVMProvider()
        elif provider == "sev-snp":
            from ._hw_providers import SEVSNPProvider
            prov = SEVSNPProvider()
        elif provider == "tdx":
            from ._hw_providers import TDXProvider
            prov = TDXProvider()
        elif provider == "opaque":
            from ._hw_providers import OPAQUEProvider
            prov = OPAQUEProvider()
        elif provider == "tpm":
            from ._providers import TPMProvider
            prov = TPMProvider()
        elif provider == "software":
            from ._auto_provider import SoftwareProvider
            prov = SoftwareProvider()
        else:  # pragma: no cover - click.Choice constrains this
            click.echo(f"Provider {provider!r} not recognized.", err=True)
            sys.exit(1)

        prov.extend_manifest_hash(data)
        report = prov.get_attestation_report()

        data["attestation"] = {
            "platform": report.platform,
            "manifest_hash_in_report": report.manifest_hash,
            "pcr_values": report.pcr_values,
            "report_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        click.echo(f"Attested on platform={report.platform}", err=True)
        _write(data, output)

    except AttestationUnavailableError as e:
        click.echo(f"Attestation unavailable: {e}", err=True)
        sys.exit(1)


@cli.command("verify")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--enforce-hitl", is_flag=True, default=False,
              help="Fail unless a required HITL approval is present and unexpired")
@click.option("--enforce-attestation", is_flag=True, default=False,
              help="Fail unless the attestation report matches the manifest hash")
@click.option("--crl-path", default=None, help="Path to a FileCRL JSON-Lines file for revocation checks")
@click.option(
    "--crl-trusted-key",
    default=None,
    help="Path to the CRL-signing authority's raw Ed25519 public key hex file. "
         "Required to cryptographically verify --crl-path records (REVOC-003); "
         "without it every record in the file is trusted unauthenticated. See "
         "the command description above for the completeness caveat.",
)
@click.option("--public-key", default=None, help="Path to a trusted raw Ed25519 public key hex file")
@click.option("--approver-key", multiple=True, metavar="APPROVER_ID=PATH",
              help="Trusted HITL approver key as approver_id=path to a raw Ed25519 "
                   "public key hex file (repeatable)")
@click.option("--require-transparency", is_flag=True, default=False,
              help="Fail unless transparency evidence was independently verified")
@click.option("--verified-transparency-entry-id", multiple=True,
              help="Legacy entry UUID independently verified for this manifest (repeatable)")
@click.option("--verified-transparency-receipt-hash", multiple=True,
              help="SHA-256 hex of a raw COSE receipt independently verified for this manifest (repeatable)")
@click.option("--transparency-evidence-manifest-id",
              help="Manifest ID to which the independent transparency appraisal was bound")
@click.option(
    "--signature-only",
    is_flag=True,
    default=False,
    help="Authenticate only the manifest signature; explicitly allow bound runtime artifacts to remain unchecked",
)
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def verify(
    manifest_file: str,
    enforce_hitl: bool,
    enforce_attestation: bool,
    crl_path: Optional[str],
    crl_trusted_key: Optional[str],
    public_key: Optional[str],
    approver_key: tuple[str, ...],
    require_transparency: bool,
    verified_transparency_entry_id: tuple[str, ...],
    verified_transparency_receipt_hash: tuple[str, ...],
    transparency_evidence_manifest_id: Optional[str],
    signature_only: bool,
    output: Optional[str],
) -> None:
    """Verify a manifest against the local verification engine.

    Prints the VerificationResult as JSON. Exits with code 0 on VALID,
    1 on any other result.

    Use --crl-path to load a revocation list and check for revoked manifests.
    Pass --crl-trusted-key with it to authenticate each record present in the
    CRL against the revoking authority's public key (spec Section 3.7 /
    REVOC-003): a record with a missing, malformed, or invalid signature
    causes verification to fail closed with an error, rather than being
    silently treated as "not revoked".

    --crl-trusted-key does NOT prove the CRL file is complete. Per-record
    signatures authenticate the records that are present but cannot detect
    that a line — or the entire file — was deleted. A party who can write or
    intercept the CRL file can still suppress a real revocation by removing
    its record entirely; only a signed, versioned CRL snapshot (not yet
    implemented) can close that gap. Without --crl-trusted-key at all, every
    line in the CRL file is additionally trusted unauthenticated: a party who
    can write or intercept that file can also fabricate a revocation for a
    legitimate manifest.


    
    HITL approvals attach outside the manifest signature, so supply the
    approver keys you trust with --approver-key. Without them an approval is
    UNVERIFIABLE and the manifest can never verify.

    
    Example:
      manifest verify attested.json --crl-path revocations.jsonl
      manifest verify signed.json --public-key pub.hex --enforce-hitl
        --approver-key mailto:alice@example.com=alice.hex
    """
    if crl_trusted_key and not crl_path:
        raise click.ClickException("--crl-trusted-key requires --crl-path.")

    subject = _load_manifest_or_envelope(manifest_file)
    trusted_keys = _trusted_key_from_public_hex(public_key) if public_key else {}
    ctx = VerificationContext(
        enforce_hitl=enforce_hitl,
        enforce_attestation=enforce_attestation,
        trusted_keys=trusted_keys,
        approver_public_keys=_approver_public_keys(approver_key),
        require_transparency=require_transparency,
        verified_transparency_entry_ids=set(verified_transparency_entry_id),
        verified_transparency_receipt_hashes=set(verified_transparency_receipt_hash),
        transparency_evidence_manifest_id=transparency_evidence_manifest_id,
        strict_artifact_verification=not signature_only,
    )

    # REVOC-001: load CRL if provided, otherwise use empty in-memory store
    store: RevocationStore
    if crl_path:
        trusted_signer_key: Optional[bytes]
        if crl_trusted_key:
            trusted_signer_key = _public_bytes_from_hex_file(
                crl_trusted_key, "CRL trusted key"
            )
        else:
            trusted_signer_key = None
            # CRL-CLI-001: FileCRL trusts every record unauthenticated when no
            # signer key is supplied (development mode). Warn loudly, because
            # unlike --public-key (whose absence forces UNVERIFIABLE) a CRL
            # with no --crl-trusted-key silently *succeeds*: a tampered or
            # incomplete CRL file un-revokes a compromised manifest instead of
            # failing closed.
            click.echo(
                "WARNING: --crl-path given without --crl-trusted-key. "
                "Revocation records are NOT cryptographically verified; any "
                "party who can write or intercept this file can suppress a "
                "real revocation or fabricate one. Pass --crl-trusted-key to "
                "authenticate records present in the CRL — note that even "
                "with --crl-trusted-key, deleting a record (or the whole "
                "file) still suppresses a revocation, since per-record "
                "signatures cannot prove the CRL is complete.",
                err=True,
            )
        try:
            store = _CRLRevocationStore(
                FileCRL(Path(crl_path), trusted_signer_key=trusted_signer_key)
            )
        except CRLIntegrityError as exc:
            # CRL-CLI-002: an authenticated CRL that fails to load must not
            # be treated as "nothing revoked". Fail the whole verify command
            # closed instead of silently proceeding as if the CRL were
            # empty (see FileCRL._load's authenticated-mode contract).
            raise click.ClickException(
                f"CRL failed integrity verification: {exc}"
            )
    else:
        store = RevocationStore()

    result = verify_manifest(subject, ctx, store)
    _write(result.model_dump(mode="json"), output)

    if result.result != OverallResult.VALID:
        click.echo(f"Result: {result.result.value}", err=True)
        if result.fields_verified.hitl_record == HitlResult.UNVERIFIABLE:
            click.echo(
                "  HINT: this manifest carries a HITL approval and no trusted "
                "approver key was supplied. Pass --approver-key "
                "APPROVER_ID=PATH for each approver you trust.",
                err=True,
            )
        for d in result.mismatch_details:
            click.echo(f"  MISMATCH {d.field}: expected {d.expected_hash[:20]}...", err=True)
        sys.exit(1)
    else:
        # A VALID result from this command authenticates the signature, but the
        # CLI never supplies runtime artifact hashes, so any bound artifact is
        # unchecked. Do not print a bare "VALID" that could be misread as proof
        # the running artifacts match the manifest (VERIFY-001).
        artifact_warning = next(
            (w for w in result.warnings if "artifact bindings NOT verified" in w),
            None,
        )
        if artifact_warning:
            click.echo(
                "Result: VALID (signature only - artifact bindings NOT verified)",
                err=True,
            )
            click.echo(
                "  WARNING: this manifest binds artifacts, but no runtime "
                "hashes were checked. The signature is authentic; the running "
                "artifacts were NOT compared against the manifest. Provide "
                "runtime hashes to verify bindings.",
                err=True,
            )
        else:
            click.echo("Result: VALID", err=True)


class _CRLRevocationStore(RevocationStore):
    """Wraps a FileCRL to satisfy the RevocationStore interface."""

    def __init__(self, crl: FileCRL) -> None:
        super().__init__()
        self._crl: FileCRL = crl

    def is_revoked(self, manifest_id: str) -> bool:
        return bool(self._crl.is_revoked(manifest_id))

    def get_record(self, manifest_id: str) -> Optional[RevocationRecord]:
        rec = self._crl.get_record(manifest_id)
        if rec is None:
            return None
        return RevocationRecord(
            manifest_id=rec.manifest_id,
            revoked_at=rec.revoked_at,
            reason=rec.reason,
            revoked_by=rec.revoked_by,
        )


@cli.command("revoke")
@click.argument("manifest_id")
@click.option("--reason", "-r", required=True, help="Reason for revocation")
@click.option("--revoked-by", required=True, help="Identity of revoking authority (DID or email)")
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def revoke(manifest_id: str, reason: str, revoked_by: str, output: Optional[str]) -> None:
    """Generate a revocation record for a manifest ID.

    The record JSON can be submitted to your revocation registry or passed
    to a RevocationStore instance in the verification endpoint.

    
    Example:
      manifest revoke 018f4a3b-... --reason "key compromise" --revoked-by security@example.com
    """
    try:
        ManifestId._validate(manifest_id)
    except ValueError as e:
        click.echo(f"Invalid manifest_id: {e}", err=True)
        sys.exit(1)

    record = RevocationRecord(
        manifest_id=manifest_id,
        revoked_at=datetime.now(timezone.utc),
        reason=reason,
        revoked_by=revoked_by,
    )
    _write(record.model_dump(mode="json"), output)
    click.echo(f"Revocation record created for {manifest_id}", err=True)


@cli.command("from-plugin")
@click.argument("bundle_dir", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def from_plugin(bundle_dir: str, output: Optional[str]) -> None:
    """Read an Agent Plugins 1.0.0 bundle and report what it can bind.

    Emits the whole-bundle digest, the skills found, and the MCP servers the
    bundle declares. It does not emit a tool manifest: mcp.json declares which
    servers to start and never enumerates their tools, so the per-tool schema
    and description hashes a tool manifest binds are not in a bundle to be read.
    Resolving those means starting the servers and asking them.

    Example:
      manifest from-plugin ./my-plugin
    """
    from ._plugins import PluginBundleError, load_plugin_bundle

    try:
        bundle = load_plugin_bundle(bundle_dir)
    except PluginBundleError as exc:
        click.echo(f"Not a usable Agent Plugins bundle: {exc}", err=True)
        sys.exit(1)

    payload: dict[str, Any] = {
        "bundle": {
            "name": bundle.name,
            "version": bundle.version,
            "schema": bundle.schema,
            "digest": bundle.digest,
        },
        "skills": [
            {"name": s.name, "path": s.relative_path, "content_hash": s.content_hash}
            for s in bundle.skills
        ],
        "declared_mcp_servers": [
            {"name": s.name, "declaration_hash": s.declaration_hash}
            for s in bundle.declared_mcp_servers
        ],
        "tool_manifest": None,
        "tool_manifest_note": (
            "A bundle declares MCP servers, not tools. A tool manifest binds a "
            "schema_hash and description_hash per tool, neither of which a bundle "
            "carries. Resolve the declared servers at runtime and bind what they "
            "actually exposed."
        ),
    }
    _write(payload, output)

    if bundle.has_resolvable_tools:
        click.echo(
            f"{len(bundle.declared_mcp_servers)} declared MCP server(s) still need "
            "resolving before a tool manifest can be bound.",
            err=True,
        )


TOP_LEVEL_COMMANDS = (
    "create", "sign", "keygen", "attest", "verify", "revoke", "from-plugin",
)


@cli.group("manifest", hidden=True)
def manifest_alias() -> None:
    """Deprecated: every command is available at the top level.

    Releases up to 0.5.0 nested the commands under a redundant ``manifest``
    group, so the real invocation was ``manifest manifest verify`` while every
    document said ``manifest verify``. The documented form is now the real one.
    This alias keeps the old spelling working for existing scripts.
    """
    click.echo(
        "Warning: 'manifest manifest <command>' is deprecated and will be "
        "removed in 1.0. Use 'manifest <command>' instead.",
        err=True,
    )


for _name in TOP_LEVEL_COMMANDS:
    _command = cli.commands[_name]
    manifest_alias.add_command(_command, _name)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
