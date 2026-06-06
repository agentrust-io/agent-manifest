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

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel

from ._canonicalize import canonicalize
from ._signing import Ed25519KeyPair

# Maximum CRL file size to prevent OOM on load (DOS-001)
_MAX_CRL_BYTES = 50 * 1024 * 1024  # 50 MB
_MAX_CRL_RECORDS = 1_000_000


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
        cryptography.exceptions.InvalidSignature: If verification fails or
            revocation_signature is absent/null (CRL-001).
    """
    import base64
    from cryptography.exceptions import InvalidSignature
    from ._signing import Ed25519Verifier as _Ed25519Verifier

    # CRL-001: null/empty signature must raise InvalidSignature, not ValueError
    if not record.revocation_signature:
        raise InvalidSignature("revocation_signature is absent or null")

    sig = record.revocation_signature
    if len(sig) < 86:  # Ed25519 sig = 64 bytes = 86 base64url chars (no padding)
        raise InvalidSignature(
            f"revocation_signature too short: {len(sig)} chars (expected ≥86)"
        )

    pre_image_obj = {
        "manifest_id": record.manifest_id,
        "revoked_at": record.revoked_at.isoformat(),
        "reason": record.reason,
        "revoked_by": record.revoked_by,
    }
    pre_image = canonicalize(pre_image_obj)

    pad = 4 - len(sig) % 4
    sig_bytes = base64.urlsafe_b64decode(sig + ("=" * pad if pad != 4 else ""))
    if len(sig_bytes) != 64:
        raise InvalidSignature(
            f"Ed25519 signature must be 64 bytes, got {len(sig_bytes)}"
        )
    # CRYPTO-007: use Ed25519Verifier so small-order key check is enforced
    _Ed25519Verifier(signer_public_key)._pub.verify(sig_bytes, pre_image)


# ---------------------------------------------------------------------------
# File-backed CRL
# ---------------------------------------------------------------------------


class FileCRL:
    """Append-only JSON-Lines CRL backed by a local file.

    Each line in the file is a JSON-serialized SignedRevocationRecord.
    The file is append-only — records are never deleted.

    For production, replace with a database-backed store and serve
    the CRL at /.well-known/agent-manifest/revocation.

    Args:
        path: Path to the CRL file. Resolved and confined at construction.
        trusted_signer_key: Raw Ed25519 public key bytes of the authority
            whose signatures are accepted on load. When provided, records
            with invalid or absent signatures are skipped (REVOC-003).
            When None, signatures are not verified (development mode only).
    """

    def __init__(
        self,
        path: str | Path,
        trusted_signer_key: Optional[bytes] = None,
    ) -> None:
        self._path = Path(path).resolve()  # INJ-008: resolve path immediately
        self._trusted_signer_key = trusted_signer_key
        self._cache: dict[str, SignedRevocationRecord] = {}
        self._lock = threading.Lock()  # REVOC-002: thread safety
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        file_size = self._path.stat().st_size
        if file_size > _MAX_CRL_BYTES:
            raise ValueError(
                f"CRL file is {file_size} bytes, exceeding the {_MAX_CRL_BYTES}-byte limit. "
                "Use a database-backed store for large CRLs."
            )

        count = 0
        with open(self._path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if count >= _MAX_CRL_RECORDS:
                    raise ValueError(
                        f"CRL file exceeds {_MAX_CRL_RECORDS} records limit."
                    )
                try:
                    rec = SignedRevocationRecord.model_validate_json(line)
                except Exception:  # nosec B112 — intentional skip of malformed lines
                    continue

                # REVOC-003: verify signature if trusted key is provided
                if self._trusted_signer_key is not None:
                    try:
                        verify_revocation_signature(rec, self._trusted_signer_key)
                    except Exception:  # nosec B112 — intentional skip of unsigned/tampered records
                        continue

                self._cache[rec.manifest_id] = rec
                count += 1

    def revoke(self, record: SignedRevocationRecord) -> None:
        """Append a revocation record to the CRL file."""
        with self._lock:
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


def create_crl_router(crl: FileCRL) -> Any:
    """Return a FastAPI router serving the CRL at /.well-known endpoints."""
    try:
        from fastapi import APIRouter, HTTPException
    except ImportError:
        raise ImportError('CRL endpoint requires FastAPI: pip install "agent-manifest[server]"')

    from ._verify import ErrorResponse

    router = APIRouter()

    @router.get("/.well-known/agent-manifest/revocation")
    async def list_revocations() -> list[dict[str, Any]]:
        """Return all revocation records as a JSON array."""
        return [r.model_dump(mode="json") for r in crl.all_records()]

    @router.get("/.well-known/agent-manifest/revocation/{manifest_id}")
    async def get_revocation(manifest_id: str) -> dict[str, Any]:
        """Return the revocation record for a specific manifest, or 404."""
        # Validate path parameter to prevent log injection (INJ-006)
        from ._types import ManifestId
        try:
            ManifestId._validate(manifest_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error_code="INVALID_MANIFEST_ID",
                    error_message="manifest_id must be a UUID v7",
                ).model_dump(),
            )
        record = crl.get_record(manifest_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="NOT_REVOKED",
                    error_message=f"No revocation record for manifest {manifest_id}",
                ).model_dump(),
            )
        return record.model_dump(mode="json")

    return router
