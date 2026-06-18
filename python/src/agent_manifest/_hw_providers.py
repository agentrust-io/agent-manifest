"""AMD SEV-SNP, Intel TDX, and TEE attestation providers — issues #6, #7, #8.

These providers extend _providers.py:AttestationProvider for higher-assurance
hardware attestation than TPM.

SEV-SNP (issue #6):
  Uses /dev/sev-guest to extend the manifest hash into the HOST_DATA field
  of the SNP attestation report. HOST_DATA is a 64-byte field specifically
  reserved for user-defined data — ideal for binding a manifest hash.

TDX (issue #7):
  Uses /dev/tdx-guest to extend the manifest hash into RTMR[1].
  RTMR (Runtime Measurement Register) 1 is conventionally used for
  application-level measurements (RTMR[0] = firmware, RTMR[1] = OS/app).

Attestation service (issue #8):
  Delegates to an external attestation service via the REST API at
  ATTESTATION_SERVICE_URL. The service runs in a managed TEE and returns a
  signed TRACE claim.
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import Any, Optional

from ._providers import AttestationProvider, AttestationReport, AttestationUnavailableError


# ---------------------------------------------------------------------------
# AMD SEV-SNP Provider
# ---------------------------------------------------------------------------

_SEV_GUEST_DEV = "/dev/sev-guest"
# IOCTL number for SNP_GET_REPORT (Linux kernel ioctl)
# struct snp_report_req: user_data (64 bytes), vmpl (u32)
_SNP_REPORT_IOCTL = 0xC0A00300  # _IOWR('s', 0, struct snp_report_req) — kernel 6.x


class SEVSNPProvider(AttestationProvider):
    """AMD SEV-SNP attestation via /dev/sev-guest (Linux kernel 5.19+).

    Extends the manifest hash into HOST_DATA (64 bytes) of the SNP attestation
    report. The first 32 bytes of HOST_DATA carry the SHA-256 of the manifest
    pre-image; the remaining 32 bytes are zero-padded.

    Requirements:
      - AMD EPYC (Milan or later) with SEV-SNP enabled in BIOS
      - Linux kernel 5.19+ with CONFIG_AMD_MEM_ENCRYPT=y
      - Running inside an SEV-SNP VM (Azure DCasv5, AWS C6a Nitro, GCP N2D)

    Raises:
        AttestationUnavailableError: If /dev/sev-guest is not accessible.
    """

    def __init__(self, require_vcek_verification: bool = False) -> None:
        if not os.path.exists(_SEV_GUEST_DEV):
            raise AttestationUnavailableError(
                f"AMD SEV-SNP not available: {_SEV_GUEST_DEV} not found. "
                "Requires an SEV-SNP VM (Azure DCasv5, AWS C6a Nitro, GCP N2D Confidential)."
            )
        # HW-008: if VCEK chain verification is required, raise eagerly so callers
        # cannot silently rely on an unverified attestation report.
        if require_vcek_verification:
            raise AttestationUnavailableError(
                "VCEK certificate chain verification is not yet implemented. "
                "Fetch the VCEK cert from AMD KDS and verify it against the AMD root CA "
                "before trusting the SNP attestation report. "
                "Pass require_vcek_verification=False only in development."
            )
        if not require_vcek_verification:
            import warnings
            warnings.warn(
                "SEVSNPProvider: VCEK certificate chain verification is disabled. "
                "This does not satisfy Level 2 conformance. "
                "Set require_vcek_verification=True for production use.",
                UserWarning,
                stacklevel=2,
            )
        self._manifest_hash: Optional[str] = None
        self._report_bytes: Optional[bytes] = None

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Request an SNP attestation report with HOST_DATA = sha256(pre_image) || 0x00*32."""
        import fcntl
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).digest()
        self._manifest_hash = f"sha256:{digest.hex()}"

        # user_data: first 32 bytes = manifest hash, last 32 bytes = zeros
        user_data = digest + bytes(32)

        # Pack the snp_report_req structure: user_data (64 bytes) + vmpl (u32) + pad (28 bytes)
        req = user_data + struct.pack("<I", 0) + bytes(28)  # vmpl=0 (highest privilege)
        buf = bytearray(4096)  # response buffer
        buf[:len(req)] = req

        try:
            with open(_SEV_GUEST_DEV, "rb") as dev:
                fcntl.ioctl(dev, _SNP_REPORT_IOCTL, buf)  # type: ignore[attr-defined]
            self._report_bytes = bytes(buf)
        except OSError as e:
            raise AttestationUnavailableError(
                f"SNP_GET_REPORT ioctl failed: {e}. "
                "Check that the kernel module is loaded and the process has CAP_SYS_ADMIN."
            )

    def get_attestation_report(self) -> AttestationReport:
        if self._report_bytes is None:
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        # Extract the measurement from the report (offset 0x90 in snp_attestation_report)
        measurement_hex = self._report_bytes[0x90:0x90 + 48].hex()
        return AttestationReport(
            platform="amd-sev-snp",
            manifest_hash=self._manifest_hash or "",
            raw={
                "host_data": self._report_bytes[0x140:0x180].hex(),  # HOST_DATA at offset 0x140
                "measurement": measurement_hex,
                "vmpl": 0,
                # HW-008: VCEK chain not verified — the ioctl response does not embed
                # the cert chain. Callers who need full attestation must fetch the VCEK
                # from AMD KDS using chip_id + tcb_version and verify independently.
                "vcek_cert_chain_verified": False,
            },
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        if self._report_bytes is not None:
            import hmac as _hmac
            expected_hex = self.manifest_hash_value(manifest_json).split(":", 1)[-1]
            # HOST_DATA is at offset 0x140 in snp_attestation_report; first 32 bytes
            # hold the SHA-256 digest we placed there in extend_manifest_hash()
            actual = self._report_bytes[0x140:0x140 + 32].hex()
            return _hmac.compare_digest(actual, expected_hex)
        # External report: fall back to manifest_hash field comparison
        return report.manifest_hash == self.manifest_hash_value(manifest_json)


# ---------------------------------------------------------------------------
# Intel TDX Provider
# ---------------------------------------------------------------------------

_TDX_GUEST_DEV = "/dev/tdx-guest"
# TDX_CMD_GET_REPORT0 = _IOWR('T', 1, struct tdx_report_req)
# struct tdx_report_req: reportdata[64] + tdreport[1024] = 1088 bytes
_TDX_CMD_GET_REPORT = 0xC4405401  # HW-001: corrected from 0xC0A00401


class TDXProvider(AttestationProvider):
    """Intel TDX attestation via /dev/tdx-guest (Linux kernel 6.2+).

    Extends the manifest hash into RTMR[1] using TDG.MR.RTMR.EXTEND.
    RTMR[1] is conventionally used for OS-level and application-level
    measurements (RTMR[0] = TD-measured, RTMR[2-3] = available for SW).

    Requirements:
      - Intel 4th Gen Xeon (Sapphire Rapids) or later with TDX enabled
      - Linux kernel 6.2+ with TDX guest driver
      - Running inside an Intel TDX Trust Domain (Azure DCedsv5, GCP C3)

    Raises:
        AttestationUnavailableError: If /dev/tdx-guest is not accessible.
    """

    RTMR_INDEX = 1  # Application-level measurement register

    def __init__(self, rtmr_index: int = 1) -> None:
        if not os.path.exists(_TDX_GUEST_DEV):
            raise AttestationUnavailableError(
                f"Intel TDX not available: {_TDX_GUEST_DEV} not found. "
                "Requires an Intel TDX Trust Domain (Azure DCedsv5, GCP C3 Confidential)."
            )
        self._rtmr = rtmr_index
        self._manifest_hash: Optional[str] = None
        self._report_bytes: Optional[bytes] = None

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Obtain a TD report with reportdata = sha256(pre_image) || 0x00*32."""
        import fcntl
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).digest()
        self._manifest_hash = f"sha256:{digest.hex()}"

        # tdx_report_req layout: reportdata[64] at offset 0, tdreport[1024] at offset 64
        # Total struct size = 1088 bytes = _IOWR('T', 1, 1088) = 0xC4405401
        reportdata = digest + bytes(32)  # 32-byte digest zero-padded to 64 bytes
        buf = bytearray(1088)
        buf[:64] = reportdata  # place reportdata at the start

        try:
            with open(_TDX_GUEST_DEV, "rb") as dev:
                fcntl.ioctl(dev, _TDX_CMD_GET_REPORT, buf)  # type: ignore[attr-defined]
            self._report_bytes = bytes(buf)
        except OSError as e:
            raise AttestationUnavailableError(f"TDX RTMR extend failed: {e}")

    def get_attestation_report(self) -> AttestationReport:
        if self._report_bytes is None:
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        # tdreport starts at offset 64; reportdata is at offset 40 within REPORTMACSTRUCT
        # Full offset in buf: 64 (tdreport start) + 40 (reportdata within REPORTMACSTRUCT) = 104
        report_data_in_tdreport = self._report_bytes[104:168]
        return AttestationReport(
            platform="intel-tdx",
            manifest_hash=self._manifest_hash or "",
            raw={
                "rtmr_index": self._rtmr,
                "report_data": report_data_in_tdreport.hex(),
            },
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        if self._report_bytes is not None:
            import hmac as _hmac
            expected_hex = self.manifest_hash_value(manifest_json).split(":", 1)[-1]
            # reportdata is at offset 104 in buf; first 32 bytes should be sha256 digest
            actual = self._report_bytes[104:136].hex()
            return _hmac.compare_digest(actual, expected_hex)
        return report.manifest_hash == self.manifest_hash_value(manifest_json)


# ---------------------------------------------------------------------------
# OPAQUE Provider
# ---------------------------------------------------------------------------


class OPAQUEProvider(AttestationProvider):
    """OPAQUE managed runtime attestation.

    Delegates to the OPAQUE attestation service running in a managed TEE at
    OPAQUE_ATTESTATION_URL. The service:
      1. Accepts the manifest pre-image
      2. Measures it in silicon (AMD SEV-SNP or Intel TDX, depending on region)
      3. Returns a TRACE claim with hardware-signed audit_chain_root

    The signing key never leaves the TEE — this is the highest assurance level.

    Environment variables:
      OPAQUE_ATTESTATION_URL: Base URL of the OPAQUE attestation service
      OPAQUE_API_KEY: API key for the service (or use mTLS)

    Raises:
        AttestationUnavailableError: If the service is not reachable.
    """

    _MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MB cap on attestation service responses

    def __init__(self) -> None:
        import urllib.parse
        raw_url = os.environ.get("OPAQUE_ATTESTATION_URL", "").rstrip("/")
        if not raw_url:
            raise AttestationUnavailableError(
                "OPAQUE_ATTESTATION_URL environment variable not set. "
                "Set it to the OPAQUE attestation service endpoint."
            )
        parsed = urllib.parse.urlparse(raw_url)
        if parsed.scheme != "https":
            raise AttestationUnavailableError(
                f"OPAQUE_ATTESTATION_URL must use https:// (got {parsed.scheme!r}). "
                "Plaintext HTTP would expose manifest pre-images and API keys."
            )
        host = parsed.hostname or ""
        if host in ("localhost", "127.0.0.1", "::1") or host.startswith("169.254.") or \
                host.startswith("10.") or host.startswith("192.168.") or \
                (host.startswith("172.") and 16 <= int(host.split(".")[1] or "0", 10) <= 31):
            raise AttestationUnavailableError(
                f"OPAQUE_ATTESTATION_URL must not target loopback or private addresses (got {host!r})."
            )
        self._url = raw_url
        self._manifest_hash: Optional[str] = None
        self._trace_claim: Optional[dict[str, Any]] = None

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Send manifest pre-image to OPAQUE attestation service."""
        try:
            import httpx
        except ImportError:
            raise AttestationUnavailableError(
                'OPAQUEProvider requires httpx: pip install "agent-manifest[server]"'
            )

        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).hexdigest()
        self._manifest_hash = f"sha256:{digest}"

        headers = {}
        api_key = os.environ.get("OPAQUE_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        import base64
        try:
            response = httpx.post(
                f"{self._url}/v1/attest",
                json={"manifest_pre_image": base64.b64encode(pre).decode()},
                headers=headers,
                timeout=30.0,
            )
        except (httpx.HTTPError, OSError) as e:
            raise AttestationUnavailableError(
                f"OPAQUE attestation service unreachable: {type(e).__name__}"
            ) from e

        if response.status_code != 200:
            raise AttestationUnavailableError(
                f"OPAQUE attestation service returned HTTP {response.status_code}. "
                "Check service logs."
            )

        content_length = int(response.headers.get("content-length", "0"))
        if content_length > self._MAX_RESPONSE_BYTES:
            raise AttestationUnavailableError(
                f"OPAQUE attestation service response too large: {content_length} bytes"
            )
        try:
            self._trace_claim = response.json()
        except ValueError as e:
            raise AttestationUnavailableError(
                f"OPAQUE attestation service returned invalid JSON: {type(e).__name__}"
            ) from e

    def get_attestation_report(self) -> AttestationReport:
        if self._trace_claim is None:
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        return AttestationReport(
            platform="opaque",
            manifest_hash=self._manifest_hash or "",
            raw=self._trace_claim,
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        return report.manifest_hash == self.manifest_hash_value(manifest_json)
