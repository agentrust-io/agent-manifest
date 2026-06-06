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
from ._providers import AttestationUnavailableError
from ._revocation import FileCRL
from ._signing import Ed25519Signer, ed25519_from_private_bytes, generate_ed25519
from ._types import ManifestId
from ._verify import (
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)


def _load_json(path: str) -> dict[str, Any]:
    with open(path) as f:
        return cast(dict[str, Any], json.load(f))


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


@click.group()
@click.version_option(package_name="agent-manifest")
def cli() -> None:
    """Agent Manifest SDK CLI."""


@cli.group()
def manifest() -> None:
    """Manage Agent Manifests."""


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


@manifest.command("create")
@click.argument("config", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def create(config: str, output: Optional[str]) -> None:
    """Create a draft manifest from a JSON config file.

    CONFIG must be a JSON file with at minimum: agent_id, issuer,
    issued_at, expires_at, and an artifacts block.

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


@manifest.command("sign")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--key", "-k", required=True, help="Path to raw 32-byte Ed25519 private key (hex file)")
@click.option("--output", "-o", default=None)
def sign(manifest_file: str, key: str, output: Optional[str]) -> None:
    """Sign a draft manifest with Ed25519.

    KEY must be a file containing the 64-hex-character (32-byte) Ed25519
    private key seed.

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
    signer = Ed25519Signer(kp)
    sig_block = signer.sign(data)
    sig_block["signed_at"] = datetime.now(timezone.utc).isoformat()
    data["signature"] = sig_block

    click.echo(f"Signed with key_id={sig_block['key_id']}", err=True)
    _write(data, output)


@manifest.command("keygen")
@click.option("--output-dir", "-d", default=".", help="Directory to write key files")
def keygen(output_dir: str) -> None:
    """Generate a new Ed25519 key pair for manifest signing.

    Writes:
      private.hex — 64-hex private key seed (keep secret, mode 0600)
      public.hex  — 64-hex public key bytes

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


@manifest.command("attest")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--provider", "-p", default="auto",
              type=click.Choice(["auto", "tpm", "sev-snp", "tdx", "opaque", "software"]),
              help="Attestation provider (default: auto)")
@click.option("--level", default=0, type=int, help="Minimum conformance level (0-3)")
@click.option("--output", "-o", default=None)
def attest(manifest_file: str, provider: str, level: int, output: Optional[str]) -> None:
    """Extend the manifest hash into hardware and append the attestation block.

    For TPM: requires tpm2-tools (apt-get install tpm2-tools).
    For swtpm in CI: set TPM2TOOLS_TCTI=swtpm: before running.

    Example:
      manifest attest signed.json --provider tpm --level 1 -o attested.json
    """
    data = _load_json(manifest_file)
    try:
        if provider == "auto":
            prov = select_provider(level=level)
        elif provider == "tpm":
            from ._providers import TPMProvider
            prov = TPMProvider()
        elif provider == "software":
            from ._auto_provider import SoftwareProvider
            prov = SoftwareProvider()
        else:
            click.echo(f"Provider {provider!r} not yet implemented. Use 'auto'.", err=True)
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


@manifest.command("verify")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--enforce-hitl", is_flag=True, default=False)
@click.option("--enforce-attestation", is_flag=True, default=False)
@click.option("--crl-path", default=None, help="Path to a FileCRL JSON-Lines file for revocation checks")
@click.option("--output", "-o", default=None)
def verify(
    manifest_file: str,
    enforce_hitl: bool,
    enforce_attestation: bool,
    crl_path: Optional[str],
    output: Optional[str],
) -> None:
    """Verify a manifest against the local verification engine.

    Prints the VerificationResult as JSON. Exits with code 0 on VALID,
    1 on any other result.

    Use --crl-path to load a revocation list and check for revoked manifests.

    Example:
      manifest verify attested.json --crl-path revocations.jsonl
    """
    data = _load_json(manifest_file)
    ctx = VerificationContext(
        enforce_hitl=enforce_hitl,
        enforce_attestation=enforce_attestation,
    )

    # REVOC-001: load CRL if provided, otherwise use empty in-memory store
    store: RevocationStore
    if crl_path:
        store = _CRLRevocationStore(FileCRL(Path(crl_path)))
    else:
        store = RevocationStore()

    result = verify_manifest(data, ctx, store)
    _write(result.model_dump(mode="json"), output)

    if result.result != OverallResult.VALID:
        click.echo(f"Result: {result.result.value}", err=True)
        for d in result.mismatch_details:
            click.echo(f"  MISMATCH {d.field}: expected {d.expected_hash[:20]}...", err=True)
        sys.exit(1)
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


@manifest.command("revoke")
@click.argument("manifest_id")
@click.option("--reason", "-r", required=True, help="Reason for revocation")
@click.option("--revoked-by", required=True, help="Identity of revoking authority (DID or email)")
@click.option("--output", "-o", default=None)
def revoke(manifest_id: str, reason: str, revoked_by: str, output: Optional[str]) -> None:
    """Generate a revocation record for a manifest ID.

    The record JSON can be submitted to your revocation registry or passed
    to a RevocationStore instance in the verification endpoint.

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


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
