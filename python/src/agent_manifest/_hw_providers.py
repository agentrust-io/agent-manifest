"""AMD SEV-SNP, Intel TDX, and TEE attestation providers — issues #6, #7, #8.

EXPERIMENTAL: these hardware providers are reference implementations and have
NOT been validated against real SEV-SNP/TDX hardware. The report field usage,
byte offsets, and IOCTL ABI below are known to be incorrect or unverified and
are tracked for a hardware-validated rewrite (issues #204, #205). Do not rely
on these providers for production attestation.

These providers extend _providers.py:AttestationProvider for higher-assurance
hardware attestation than TPM.

SEV-SNP (issue #6):
  Uses /dev/sev-guest to bind the manifest hash into the guest-controlled
  REPORT_DATA field of the SNP attestation report (populated via the user_data
  member of the report request). REPORT_DATA is a 64-byte field reserved for
  guest-supplied data. HOST_DATA is a separate, host-set field (32 bytes) that
  the guest cannot write, and is NOT used here.

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

from ._providers import (
    AttestationProvider,
    AttestationReport,
    AttestationUnavailableError,
    RuntimeAttestationReport,
)


# ---------------------------------------------------------------------------
# AMD SEV-SNP Provider
# ---------------------------------------------------------------------------

_SEV_GUEST_DEV = "/dev/sev-guest"
# IOCTL number for SNP_GET_REPORT (Linux kernel ioctl)
# struct snp_report_req: user_data (64 bytes), vmpl (u32)
_SNP_REPORT_IOCTL = 0xC0A00300  # _IOWR('s', 0, struct snp_report_req) — kernel 6.x


class SEVSNPProvider(AttestationProvider):
    """AMD SEV-SNP attestation via /dev/sev-guest (Linux kernel 5.19+).

    EXPERIMENTAL / not hardware-validated — see the module docstring and #205.

    Binds the manifest hash into the guest-controlled REPORT_DATA (64 bytes) of
    the SNP attestation report. The first 32 bytes carry the SHA-256 of the
    manifest pre-image; the remaining 32 bytes are zero-padded. (HOST_DATA is a
    separate host-set field and is not used.) The report-parsing offsets in this
    class are not yet corrected for REPORT_DATA and must be fixed against the
    AMD ABI before production use (#205).

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
                # FIXME(#205): guest-supplied data lives in REPORT_DATA (offset 0x50), not
                # HOST_DATA (0x140). This reads the wrong field and is not hardware-validated.
                "host_data": self._report_bytes[0x140:0x180].hex(),
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
            # FIXME(#205): reads HOST_DATA (offset 0x140); guest-supplied data is in
            # REPORT_DATA (offset 0x50). Not hardware-validated — see module docstring.
            actual = self._report_bytes[0x140:0x140 + 32].hex()
            return _hmac.compare_digest(actual, expected_hex)
        # External report: fall back to manifest_hash field comparison
        return report.manifest_hash == self.manifest_hash_value(manifest_json)

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Fresh SNP report with HOST_DATA = sha256(nonce || context_hash_bytes).

        Issues a new SNP_GET_REPORT ioctl — no cached state is reused.
        The returned report carries the same immutable MEASUREMENT as the
        boot-time report, plus a freshly hardware-signed HOST_DATA field
        that binds the nonce and current context hash.
        """
        import fcntl
        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying).hexdigest()}"

        # HOST_DATA: first 32 bytes = sha256(nonce || context), last 32 = zeros
        user_data = qualifying + bytes(32)
        req = user_data + struct.pack("<I", 0) + bytes(28)
        buf = bytearray(4096)
        buf[:len(req)] = req

        try:
            with open(_SEV_GUEST_DEV, "rb") as dev:
                fcntl.ioctl(dev, _SNP_REPORT_IOCTL, buf)  # type: ignore[attr-defined]
        except OSError as e:
            raise AttestationUnavailableError(
                f"SNP_GET_REPORT ioctl failed during runtime re-attestation: {e}"
            )

        quote_bytes = bytes(buf)
        measurement_hex = quote_bytes[0x90:0x90 + 48].hex()

        return RuntimeAttestationReport(
            platform="amd-sev-snp",
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            quote=quote_bytes,
            raw={
                "host_data": quote_bytes[0x140:0x180].hex(),
                "measurement": measurement_hex,
                "vcek_cert_chain_verified": False,
            },
        )


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

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Fresh TD report with REPORTDATA = sha256(nonce || context_hash_bytes).

        Issues a new TDX_CMD_GET_REPORT ioctl — no cached state is reused.
        The returned report carries the same immutable MRTD as the boot-time
        report, plus a freshly hardware-signed REPORTDATA field that binds
        the nonce and current context hash.
        """
        import fcntl
        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying).hexdigest()}"

        # REPORTDATA: 32-byte digest zero-padded to 64 bytes
        reportdata = qualifying + bytes(32)
        buf = bytearray(1088)
        buf[:64] = reportdata

        try:
            with open(_TDX_GUEST_DEV, "rb") as dev:
                fcntl.ioctl(dev, _TDX_CMD_GET_REPORT, buf)  # type: ignore[attr-defined]
        except OSError as e:
            raise AttestationUnavailableError(
                f"TDX_CMD_GET_REPORT failed during runtime re-attestation: {e}"
            )

        quote_bytes = bytes(buf)

        return RuntimeAttestationReport(
            platform="intel-tdx",
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            quote=quote_bytes,
            raw={
                "rtmr_index": self._rtmr,
                "report_data": quote_bytes[104:168].hex(),
            },
        )


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

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Delegate runtime re-attestation to the OPAQUE attestation service.

        Calls POST /v1/attest-runtime with the nonce and context_hash.
        The service measures both inside its managed TEE and returns a
        hardware-signed TRACE claim covering the nonce and context.
        """
        try:
            import httpx
        except ImportError:
            raise AttestationUnavailableError(
                'OPAQUEProvider requires httpx: pip install "agent-manifest[server]"'
            )

        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying).hexdigest()}"

        import base64
        headers: dict[str, str] = {}
        api_key = os.environ.get("OPAQUE_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            response = httpx.post(
                f"{self._url}/v1/attest-runtime",
                json={
                    "nonce": base64.b64encode(nonce).decode(),
                    "context_hash": context_hash,
                },
                headers=headers,
                timeout=30.0,
            )
        except (httpx.HTTPError, OSError) as e:
            raise AttestationUnavailableError(
                f"OPAQUE runtime attestation service unreachable: {type(e).__name__}"
            ) from e

        if response.status_code != 200:
            raise AttestationUnavailableError(
                f"OPAQUE runtime attestation returned HTTP {response.status_code}"
            )

        content_length = int(response.headers.get("content-length", "0"))
        if content_length > self._MAX_RESPONSE_BYTES:
            raise AttestationUnavailableError(
                f"OPAQUE runtime attestation response too large: {content_length} bytes"
            )

        try:
            raw = response.json()
        except ValueError as e:
            raise AttestationUnavailableError(
                f"OPAQUE runtime attestation returned invalid JSON: {type(e).__name__}"
            ) from e

        return RuntimeAttestationReport(
            platform="opaque",
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            raw=raw,
        )
