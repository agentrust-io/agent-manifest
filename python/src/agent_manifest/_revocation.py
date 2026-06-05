"""Revocation CRL endpoint and signed revocation record — issue #14.

The RevocationRecord in _verify.py is the in-memory model. This module adds:
  - Signed revocation records (the revoking authority signs the record)
  - CRL (Certificate Revocation List) endpoint — a JSON-Lines file of records
  - Discovery: .well-known/agent-manifest/revocation endpoint
  - Persistence: file-backed CRL for the SDK-hosted mode

Spec Section 3.7 (added in PR improving the spec) defines the revocation
mechanism. The CRL format follows RFC 5280 conceptually but uses JSON.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from ._canonicalize import canonicalize
from ._signing import Ed25519KeyPair


# ---------------------------------------------------------------------------
# Signed revocation record
# ---------------------------------------------------------------------------


class SignedRevocationRecord(BaseModel):
    """A revocation record signed by the revoking authority.

    The signature covers the canonical form of the record fields,
    binding the revocation to a specific manifest and authority.
    """

    manifest_id: str
    revoked_at: datetime
    reason: str
    revoked_by: str  # DID, email, or SPIFFE URI of the revoking authority
    revocation_signature: Optional[str] = None  # base64url Ed25519 sig
    signer_key_id: Optional[str] = None  # sha256 of signer's public key


def sign_revocation(
    manifest_id: str,
    reason: str,
    revoked_by: str,
    keypair: Ed25519KeyPair,
) -> SignedRevocationRecord:
    """Create and sign a revocation record."""
    import base64

    revoked_at = datetime.now(timezone.utc)
    pre_image_obj = {
        "manifest_id": manifest_id,
        "revoked_at": revoked_at.isoformat(),
        "reason": reason,
        "revoked_by": revoked_by,
    }
    pre_image = canonicalize(pre_image_obj)
    sig_bytes = keypair.private_key.sign(pre_image)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    return SignedRevocationRecord(
        manifest_id=manifest_id,
        revoked_at=revoked_at,
        reason=reason,
        revoked_by=revoked_by,
        revocation_signature=sig_b64,
        signer_key_id=keypair.key_id,
    )


def verify_revocation_signature(
    record: SignedRevocationRecord,
    signer_public_key: bytes,
) -> None:
    """Verify the signature on a signed revocation record.

    Raises:
        cryptography.exceptions.InvalidSignature: If verification fails.
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    pre_image_obj = {
        "manifest_id": record.manifest_id,
        "revoked_at": record.revoked_at.isoformat(),
        "reason": record.reason,
        "revoked_by": record.revoked_by,
    }
    pre_image = canonicalize(pre_image_obj)

    sig = record.revocation_signature or ""
    pad = 4 - len(sig) % 4
    sig_bytes = base64.urlsafe_b64decode(sig + ("=" * pad if pad != 4 else ""))
    pub = Ed25519PublicKey.from_public_bytes(signer_public_key)
    pub.verify(sig_bytes, pre_image)


# ---------------------------------------------------------------------------
# File-backed CRL
# ---------------------------------------------------------------------------


class FileCRL:
    """Append-only JSON-Lines CRL backed by a local file.

    Each line in the file is a JSON-serialized SignedRevocationRecord.
    The file is append-only — records are never deleted.

    For production, replace with a database-backed store and serve
    the CRL at /.well-known/agent-manifest/revocation.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._cache: dict[str, SignedRevocationRecord] = {}
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if line:
                    rec = SignedRevocationRecord.model_validate_json(line)
                    self._cache[rec.manifest_id] = rec

    def revoke(self, record: SignedRevocationRecord) -> None:
        """Append a revocation record to the CRL file."""
        self._cache[record.manifest_id] = record
        with open(self._path, "a") as f:
            f.write(record.model_dump_json() + "\n")

    def is_revoked(self, manifest_id: str) -> bool:
        return manifest_id in self._cache

    def get_record(self, manifest_id: str) -> Optional[SignedRevocationRecord]:
        return self._cache.get(manifest_id)

    def all_records(self) -> list[SignedRevocationRecord]:
        return list(self._cache.values())


# ---------------------------------------------------------------------------
# FastAPI CRL router
# ---------------------------------------------------------------------------


def create_crl_router(crl: FileCRL):
    """Return a FastAPI router serving the CRL at /.well-known endpoints."""
    try:
        from fastapi import APIRouter, HTTPException, Query
    except ImportError:
        raise ImportError('CRL endpoint requires FastAPI: pip install "agent-manifest[server]"')

    from ._verify import ErrorResponse

    router = APIRouter()

    @router.get("/.well-known/agent-manifest/revocation")
    async def list_revocations():
        """Return all revocation records as a JSON array."""
        return [r.model_dump(mode="json") for r in crl.all_records()]

    @router.get("/.well-known/agent-manifest/revocation/{manifest_id}")
    async def get_revocation(manifest_id: str):
        """Return the revocation record for a specific manifest, or 404."""
        record = crl.get_record(manifest_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="NOT_REVOKED",
                    error_message=f"No revocation record for {manifest_id}",
                ).model_dump(),
            )
        return record.model_dump(mode="json")

    return router
