"""Rekor/Sigstore transparency log integration — issue #11.

Spec Section 3.6 requires all production manifests to be published to a
public or consortium transparency log before the signature is considered
sufficient for regulatory purposes.

Ordering fix (spec #37 / SPEC-10):
  The manifest is signed BEFORE the transparency log entry is created —
  the entry is appended to the manifest post-signing as a separate
  top-level field (transparency_log_entry). The signed_fields do NOT
  include transparency_log_entry, which closes the chicken-and-egg
  ordering problem.

Sigstore bundle compatibility (spec #43):
  The TransparencyLogEntry model includes `checkpoint` and `integrated_time`
  fields required by Sigstore bundle format (sigstore-bundle v0.3+).

ML-DSA-65 note (spec #44):
  Public Rekor does not currently support ML-DSA-65. For Level 3
  (post-quantum) deployments, use a private Rekor instance or document
  the alternative log in transparency_log_entry.log_id.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Optional

# Rekor default endpoint
REKOR_PUBLIC_URL = "https://rekor.sigstore.dev"
REKOR_API_PATH = "/api/v1/log/entries"


@dataclass
class TransparencyLogEntry:
    """Transparency log entry appended post-signing (not in signed_fields)."""

    log_id: str
    entry_id: str
    inclusion_proof: str  # base64url-encoded Merkle inclusion proof
    # Sigstore bundle v0.3 compatibility fields (spec #43)
    checkpoint: Optional[str] = None
    integrated_time: Optional[int] = None
    log_index: Optional[int] = None


def publish_to_rekor(
    manifest_dict: dict[str, Any],
    signature_value: str,
    public_key_b64url: str,
    rekor_url: str = REKOR_PUBLIC_URL,
) -> TransparencyLogEntry:
    """Publish the manifest signature to the Rekor transparency log.

    The payload submitted to Rekor is the RFC 8785 canonical JSON of
    signed_fields only (not the full manifest), matching the exact bytes
    that were signed.

    Args:
        manifest_dict: Full manifest including signature block.
        signature_value: base64url-encoded Ed25519 signature.
        public_key_b64url: base64url-encoded Ed25519 public key.
        rekor_url: Rekor instance URL.

    Returns:
        TransparencyLogEntry to append to the manifest.

    Raises:
        RuntimeError: If the Rekor API call fails.
        ImportError: If httpx is not installed.
    """
    try:
        import httpx
    except ImportError:
        raise ImportError(
            "Rekor integration requires httpx. "
            'Install with: pip install "agent-manifest[server]"'
        )

    from ._canonicalize import canonicalize
    from ._signing import SIGNED_FIELDS

    # Build the signed bytes (must match what was signed)
    subset = {k: manifest_dict[k] for k in SIGNED_FIELDS if k in manifest_dict}
    canonical_bytes = canonicalize(subset)
    canonical_b64 = base64.b64encode(canonical_bytes).decode()

    # Decode public key from base64url to PEM for Rekor
    pad = 4 - len(public_key_b64url) % 4
    pub_raw = base64.urlsafe_b64decode(public_key_b64url + ("=" * pad if pad != 4 else ""))
    pub_pem = _raw_ed25519_to_pem(pub_raw)

    # Rekor hashedrekord entry format
    content_hash = hashlib.sha256(canonical_bytes).hexdigest()
    entry = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {
                "hash": {"algorithm": "sha256", "value": content_hash}
            },
            "signature": {
                "content": signature_value,
                "publicKey": {"content": base64.b64encode(pub_pem).decode()},
            },
        },
    }

    response = httpx.post(
        f"{rekor_url}{REKOR_API_PATH}",
        json=entry,
        headers={"Content-Type": "application/json"},
        timeout=30.0,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(
            f"Rekor submission failed: {response.status_code} {response.text[:200]}"
        )

    body = response.json()
    # Rekor returns a dict keyed by entry UUID
    entry_uuid = next(iter(body))
    entry_data = body[entry_uuid]
    body_decoded = json.loads(base64.b64decode(entry_data.get("body", "")))

    return TransparencyLogEntry(
        log_id=entry_data.get("logID", rekor_url),
        entry_id=entry_uuid,
        inclusion_proof=base64.urlsafe_b64encode(
            json.dumps(entry_data.get("inclusionProof", {})).encode()
        ).rstrip(b"=").decode(),
        checkpoint=entry_data.get("checkpoint"),
        integrated_time=entry_data.get("integratedTime"),
        log_index=entry_data.get("logIndex"),
    )


def verify_transparency_log_entry(
    manifest_dict: dict[str, Any],
    entry: TransparencyLogEntry,
    rekor_url: str = REKOR_PUBLIC_URL,
) -> bool:
    """Verify that the manifest entry exists in the transparency log.

    Fetches the entry from Rekor and checks that the content hash
    matches the canonical signed bytes.

    Returns:
        True if the entry is present and valid.
    """
    try:
        import httpx
    except ImportError:
        raise ImportError("Rekor verification requires httpx.")

    from ._canonicalize import canonicalize
    from ._signing import SIGNED_FIELDS

    subset = {k: manifest_dict[k] for k in SIGNED_FIELDS if k in manifest_dict}
    canonical_bytes = canonicalize(subset)
    expected_hash = hashlib.sha256(canonical_bytes).hexdigest()

    try:
        response = httpx.get(
            f"{rekor_url}{REKOR_API_PATH}/{entry.entry_id}",
            timeout=15.0,
        )
    except Exception:
        return False

    if response.status_code != 200:
        return False

    body = response.json()
    entry_data = next(iter(body.values()), {})
    decoded = json.loads(base64.b64decode(entry_data.get("body", "e30=")))
    actual_hash = (
        decoded.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
    )
    return actual_hash == expected_hash


def _raw_ed25519_to_pem(raw_public_key: bytes) -> bytes:
    """Wrap a 32-byte raw Ed25519 public key in SubjectPublicKeyInfo DER+PEM."""
    # SubjectPublicKeyInfo for Ed25519 (OID 1.3.101.112)
    SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
    der = SPKI_PREFIX + raw_public_key
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    pem = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
    return pem.encode()
