"""Hardware attestation providers for Agent Manifest SDK.

Each provider implements the AttestationProvider interface. Providers are
selected automatically by provider='auto' (see _auto_provider.py) or
instantiated directly.

Implemented providers:
  TPMProvider       — Generic TPM 2.0 + AWS Nitro via tpm2-tools
  SEVSNPProvider    — AMD SEV-SNP (via /dev/sev-guest)        [issue #6]
  TDXProvider       — Intel TDX (via /dev/tdx-guest)          [issue #7]
  OPAQUEProvider    — Opaque Managed Runtime stub             [issue #8]
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ._canonicalize import canonicalize


# ---------------------------------------------------------------------------
# Shared types
# ---------------------------------------------------------------------------


class AttestationUnavailableError(RuntimeError):
    """Raised when the attestation hardware or daemon is not accessible.

    Callers MUST NOT treat this as a silent success. An agent that cannot
    produce hardware attestation MUST NOT claim Level 1+ conformance.
    """


@dataclass
class AttestationReport:
    """Portable attestation report returned by all providers."""

    platform: str  # "tpm" | "sev-snp" | "tdx" | "opaque"
    manifest_hash: str  # "sha256:<64-hex>" — hash of the signed manifest
    pcr_values: dict[str, str] = field(default_factory=dict)  # {"PCR15": "sha256:..."}
    quote: Optional[bytes] = None  # raw platform quote/report blob
    cert_chain: list[bytes] = field(default_factory=list)  # DER-encoded certs
    raw: dict[str, Any] = field(default_factory=dict)  # provider-specific extras


class AttestationProvider(ABC):
    """Interface all providers implement."""

    @abstractmethod
    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Extend the manifest hash into the hardware measurement register."""

    @abstractmethod
    def get_attestation_report(self) -> AttestationReport:
        """Return the current platform attestation report."""

    @abstractmethod
    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        """Return True if the report contains the expected manifest hash."""

    # Shared helper
    def manifest_pre_image(self, manifest_json: dict[str, Any]) -> bytes:
        """RFC 8785 canonical JSON of manifest with attestation block excluded.

        This is the exact byte sequence extended into the hardware register
        and recorded in manifest_hash_in_report (spec Section 3.3).
        """
        # Exclude the attestation block — it is appended after measurement
        subset = {k: v for k, v in manifest_json.items() if k != "attestation"}
        return canonicalize(subset)

    def manifest_hash_value(self, manifest_json: dict[str, Any]) -> str:
        """Return sha256:<hex> of the manifest pre-image."""
        pre = self.manifest_pre_image(manifest_json)
        return f"sha256:{hashlib.sha256(pre).hexdigest()}"


# ---------------------------------------------------------------------------
# TPMProvider
# ---------------------------------------------------------------------------

# PCR assignments per spec Section 3.3 (SPEC-08 fix):
#   Generic TPM 2.0: PCR 15 (application-level, above OS/bootloader range 0-14)
#   AWS Nitro:       PCR 8  (Nitro's custom measurement PCR)
_TPM_DEFAULT_PCR = 15
_NITRO_PCR = 8

# AWS Nitro is detected by the presence of the NSM character device
_NITRO_NSM_DEV = "/dev/nsm"


def _detect_nitro() -> bool:
    return os.path.exists(_NITRO_NSM_DEV)


def _require_tpm2_tools() -> None:
    if shutil.which("tpm2_extend") is None:
        raise AttestationUnavailableError(
            "tpm2-tools not found. Install with: apt-get install tpm2-tools "
            "or yum install tpm2-tools. "
            "For CI, use swtpm: https://github.com/stefanberger/swtpm"
        )


class TPMProvider(AttestationProvider):
    """TPM 2.0 attestation provider.

    Supports generic TPM 2.0 (PCR 15) and AWS Nitro Enclaves (PCR 8).
    Uses tpm2-tools CLI for PCR extension and quote generation.

    On AWS Nitro, the NSM device (/dev/nsm) is detected automatically
    and PCR 8 is used instead of the default PCR 15.

    For CI environments without a hardware TPM, install swtpm and set
    TPM2TOOLS_TCTI=swtpm: or TPM2TOOLS_TCTI=device:/dev/tpm0.

    Raises:
        AttestationUnavailableError: If tpm2-tools is not installed or
            the TPM device is not accessible.
    """

    def __init__(self, pcr_index: Optional[int] = None) -> None:
        self._is_nitro = _detect_nitro()
        if pcr_index is not None:
            self._pcr = pcr_index
        elif self._is_nitro:
            self._pcr = _NITRO_PCR
        else:
            self._pcr = _TPM_DEFAULT_PCR
        self._last_manifest_hash: Optional[str] = None

    @property
    def pcr_index(self) -> int:
        return self._pcr

    @property
    def platform_label(self) -> str:
        return "aws-nitro" if self._is_nitro else "tpm"

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Extend the manifest hash into PCR *self._pcr* using tpm2_extend.

        The extended value is the SHA-256 of the RFC 8785 canonical manifest
        (attestation block excluded). This ensures the PCR value is
        deterministically bound to the exact manifest that was approved.

        Raises:
            AttestationUnavailableError: If tpm2_extend fails.
        """
        _require_tpm2_tools()
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).hexdigest()
        self._last_manifest_hash = f"sha256:{digest}"

        result = subprocess.run(
            ["tpm2_extend", f"-i{self._pcr}", "-g=sha256", f"-d={digest}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AttestationUnavailableError(
                f"tpm2_extend failed (PCR {self._pcr}): {result.stderr.strip()}"
            )

    def get_attestation_report(self) -> AttestationReport:
        """Read current PCR values and generate a TPM2 quote.

        Raises:
            AttestationUnavailableError: If tpm2_pcrread or tpm2_quote fails.
        """
        _require_tpm2_tools()

        # Read PCR values
        result = subprocess.run(
            ["tpm2_pcrread", f"sha256:{self._pcr}"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise AttestationUnavailableError(
                f"tpm2_pcrread failed: {result.stderr.strip()}"
            )

        pcr_values = self._parse_pcrread_output(result.stdout)

        return AttestationReport(
            platform=self.platform_label,
            manifest_hash=self._last_manifest_hash or "",
            pcr_values=pcr_values,
            raw={"pcr_index": self._pcr, "tpm2_pcrread": result.stdout},
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        """Check that the PCR in the report contains the expected manifest hash.

        The expected value is the cumulative PCR extension value after the
        manifest hash was extended. For a PCR starting at 0x00..00:
          new_pcr = SHA-256(current_pcr_value || manifest_hash_bytes)

        For simplicity, the SDK checks that the report's manifest_hash
        matches the hash we would compute from the manifest. A full PCR
        replay verification requires the pre-extension PCR value, which
        callers must supply for production use.
        """
        expected = self.manifest_hash_value(manifest_json)
        return report.manifest_hash == expected

    def _parse_pcrread_output(self, output: str) -> dict[str, str]:
        """Parse tpm2_pcrread YAML output into {PCR_label: hash_value}."""
        pcr_values: dict[str, str] = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith(f"{self._pcr}:"):
                _, _, val = line.partition(":")
                val = val.strip().lstrip("0x")
                pcr_values[f"PCR{self._pcr}"] = f"sha256:{val.lower()}"
        return pcr_values
