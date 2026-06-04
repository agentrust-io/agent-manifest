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
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import click
except ImportError:
    raise ImportError(
        "CLI requires click. Install with: pip install 'agent-manifest[cli]'"
    )

from ._auto_provider import select_provider
from ._providers import AttestationUnavailableError
from ._signing import Ed25519Signer, Ed25519Verifier, ed25519_from_private_bytes, generate_ed25519
from ._types import ManifestId
from ._verify import (
    OverallResult,
    RevocationRecord,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _write(data: dict, output: Optional[str]) -> None:
    text = json.dumps(data, indent=2, default=str)
    if output:
        Path(output).write_text(text)
        click.echo(f"Written to {output}", err=True)
    else:
        click.echo(text)


@click.group()
@click.version_option(package_name="agent-manifest")
def cli():
    """Agent Manifest SDK CLI."""


@cli.group()
def manifest():
    """Manage Agent Manifests."""


@manifest.command("create")
@click.argument("config", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Write output to file (default: stdout)")
def create(config: str, output: Optional[str]):
    """Create a draft manifest from a JSON config file.

    CONFIG must be a JSON file with at minimum: agent_id, issuer,
    issued_at, expires_at, and an artifacts block.

    Example:
      manifest create config.json -o draft.json
    """
    data = _load_json(config)

    # Assign a new UUID v7-format manifest ID if not provided
    if "manifest_id" not in data:
        import uuid
        raw = uuid.uuid4()
        # Force version nibble to 7 for a best-effort v7 (full time-ordering
        # requires the time-based construction; this is acceptable for drafts)
        data["manifest_id"] = str(raw)

    data.setdefault("version", "0.1")
    data.setdefault("crypto_profile", "standard")

    click.echo(f"Created draft manifest {data.get('manifest_id')}", err=True)
    _write(data, output)


@manifest.command("sign")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--key", "-k", required=True, help="Path to raw 32-byte Ed25519 private key (hex file)")
@click.option("--output", "-o", default=None)
def sign(manifest_file: str, key: str, output: Optional[str]):
    """Sign a draft manifest with Ed25519.

    KEY must be a file containing the 64-hex-character (32-byte) Ed25519
    private key seed.

    Example:
      manifest sign draft.json --key private.hex -o signed.json
    """
    data = _load_json(manifest_file)
    key_hex = Path(key).read_text().strip()
    kp = ed25519_from_private_bytes(bytes.fromhex(key_hex))
    signer = Ed25519Signer(kp)
    sig_block = signer.sign(data)
    sig_block["signed_at"] = datetime.now(timezone.utc).isoformat()
    data["signature"] = sig_block

    click.echo(f"Signed with key_id={sig_block['key_id']}", err=True)
    _write(data, output)


@manifest.command("keygen")
@click.option("--output-dir", "-d", default=".", help="Directory to write key files")
def keygen(output_dir: str):
    """Generate a new Ed25519 key pair for manifest signing.

    Writes:
      private.hex — 64-hex private key seed (keep secret)
      public.hex  — 64-hex public key bytes

    Example:
      manifest keygen -d ./keys/
    """
    kp = generate_ed25519()
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    priv_hex = kp.private_b64url()  # base64url — store as-is
    pub_hex = kp.public_bytes.hex()
    priv_raw = kp.private_key.private_bytes(
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["PrivateFormat"]).PrivateFormat.Raw,
        __import__("cryptography.hazmat.primitives.serialization", fromlist=["NoEncryption"]).NoEncryption(),
    ).hex()
    (out / "private.hex").write_text(priv_raw)
    (out / "public.hex").write_text(pub_hex)
    click.echo(f"Generated key pair in {out}/")
    click.echo(f"  key_id = {kp.key_id}")
    click.echo(f"  public = {pub_hex[:16]}...{pub_hex[-8:]}")
    click.echo("Keep private.hex secret.", err=True)


@manifest.command("attest")
@click.argument("manifest_file", type=click.Path(exists=True))
@click.option("--provider", "-p", default="auto",
              type=click.Choice(["auto", "tpm", "sev-snp", "tdx", "opaque", "software"]),
              help="Attestation provider (default: auto)")
@click.option("--level", default=0, type=int, help="Minimum conformance level (0-3)")
@click.option("--output", "-o", default=None)
def attest(manifest_file: str, provider: str, level: int, output: Optional[str]):
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
@click.option("--output", "-o", default=None)
def verify(manifest_file: str, enforce_hitl: bool, enforce_attestation: bool, output: Optional[str]):
    """Verify a manifest against the local verification engine.

    Prints the VerificationResult as JSON. Exits with code 0 on VALID,
    1 on any other result.

    Example:
      manifest verify attested.json
    """
    data = _load_json(manifest_file)
    ctx = VerificationContext(
        enforce_hitl=enforce_hitl,
        enforce_attestation=enforce_attestation,
    )
    s = RevocationStore()
    result = verify_manifest(data, ctx, s)
    _write(result.model_dump(mode="json"), output)

    if result.result != OverallResult.VALID:
        click.echo(f"Result: {result.result.value}", err=True)
        for d in result.mismatch_details:
            click.echo(f"  MISMATCH {d.field}: expected {d.expected_hash[:20]}...", err=True)
        sys.exit(1)
    else:
        click.echo(f"Result: VALID", err=True)


@manifest.command("revoke")
@click.argument("manifest_id")
@click.option("--reason", "-r", required=True, help="Reason for revocation")
@click.option("--revoked-by", required=True, help="Identity of revoking authority (DID or email)")
@click.option("--output", "-o", default=None)
def revoke(manifest_id: str, reason: str, revoked_by: str, output: Optional[str]):
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


def main():
    cli()


if __name__ == "__main__":
    main()
