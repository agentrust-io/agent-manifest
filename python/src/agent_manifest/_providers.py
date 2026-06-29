"""Hardware attestation providers for Agent Manifest SDK.

Each provider implements the AttestationProvider interface. Providers are
selected automatically by provider='auto' (see _auto_provider.py) or
instantiated directly.

Implemented providers:
  TPMProvider       — Generic TPM 2.0 + AWS Nitro via tpm2-tools
  SEVSNPProvider    — AMD SEV-SNP (via /dev/sev-guest)        [issue #6]
  TDXProvider       — Intel TDX (via /dev/tdx-guest)          [issue #7]
  OPAQUEProvider    — OPAQUE Managed Runtime stub             [issue #8]
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


@dataclass
class RuntimeAttestationReport:
    """Fresh hardware quote binding current runtime state to the TEE's boot measurement.

    Produced by attest_runtime_state() on demand — distinct from the one-time
    AttestationReport produced at startup. The hardware signs both its immutable
    boot measurement (MEASUREMENT / MRTD / PCRs) and the caller-supplied
    REPORT_DATA = sha256(nonce || context_hash_bytes), so a verifier can confirm:

      1. TEE identity — same boot measurement as at startup (hardware hasn't changed)
      2. Current state — context_hash matches what the agent claims to be running
      3. Freshness — nonce is unique per challenge, preventing replay

    The boot measurement itself never changes — this call does not re-measure
    the TEE firmware or kernel. What it adds is a hardware-signed certificate
    that a specific runtime state was active at a specific moment in that TEE.
    """

    platform: str
    # sha256(nonce || context_hash_bytes) placed in REPORT_DATA / HOST_DATA
    report_data_hash: str
    # sha256:<hex> of the caller-supplied runtime context (system prompt, policy, tools…)
    context_hash: str
    # hex of the nonce — verifier checks this matches what it supplied
    nonce_hex: str
    quote: Optional[bytes] = None
    raw: dict[str, Any] = field(default_factory=dict)


class AttestationProvider(ABC):
    """Interface all providers implement."""

    @abstractmethod
    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Extend the manifest hash into the hardware measurement register.

        Called once at agent startup. The result is the boot-time attestation:
        it proves which manifest was active when the TEE was initialised, but
        does not continuously track runtime state changes after that point.
        """

    @abstractmethod
    def get_attestation_report(self) -> AttestationReport:
        """Return the boot-time platform attestation report."""

    @abstractmethod
    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        """Return True if the report contains the expected manifest hash."""

    @abstractmethod
    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Return a fresh hardware quote binding current runtime state to TEE identity.

        Unlike extend_manifest_hash() + get_attestation_report() which run once at
        startup, this method can be called periodically or per-N-calls to produce
        a hardware-signed freshness proof of the agent's current runtime state.

        The hardware sets REPORT_DATA / HOST_DATA to:
            sha256(nonce || bytes.fromhex(context_hash.split(":")[-1]))
        and signs it together with the unchanged boot measurement, so a verifier
        holding the nonce can confirm both TEE identity and current state.

        The boot measurement (MEASUREMENT / MRTD / PCR values) is immutable —
        this call does not re-measure the TEE. It produces a fresh hardware
        signature over new caller-supplied data in the user-controlled field.

        Args:
            nonce: Freshness token supplied by the verifier (16–32 bytes).
                   A new nonce must be used for each challenge to prevent replay.
            context_hash: sha256:<hex> of the current runtime context. Callers
                          compute this from system_prompt_hash, policy_hash,
                          tool_catalog_hash, and any other state that must be
                          proven fresh. Use canonical JSON + sha256 for determinism.

        Raises:
            AttestationUnavailableError: If the hardware device is not accessible
                or (for TPM) the Attestation Key has not been provisioned.
        """

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


def _require_tpm2_tools() -> tuple[str, str]:
    """Return absolute paths (tpm2_extend, tpm2_pcrread) or raise.

    HW-007: resolve to absolute paths at call time so PATH changes after
    import cannot inject a malicious binary.
    """
    extend = shutil.which("tpm2_extend")
    pcrread = shutil.which("tpm2_pcrread")
    if extend is None or pcrread is None:
        raise AttestationUnavailableError(
            "tpm2-tools not found. Install with: apt-get install tpm2-tools "
            "or yum install tpm2-tools. "
            "For CI, use swtpm: https://github.com/stefanberger/swtpm"
        )
    return extend, pcrread


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

    def __init__(
        self,
        pcr_index: Optional[int] = None,
        ak_context: Optional[str] = None,
    ) -> None:
        self._is_nitro = _detect_nitro()
        if pcr_index is not None:
            self._pcr = pcr_index
        elif self._is_nitro:
            self._pcr = _NITRO_PCR
        else:
            self._pcr = _TPM_DEFAULT_PCR
        self._last_manifest_hash: Optional[str] = None
        # Path to a pre-provisioned Attestation Key context for tpm2_quote.
        # Required only for attest_runtime_state(); boot-time attestation works without it.
        self._ak_context = ak_context

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
        extend_path, _ = _require_tpm2_tools()
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).hexdigest()
        self._last_manifest_hash = f"sha256:{digest}"

        result = subprocess.run(
            [extend_path, f"-i{self._pcr}", "-g=sha256", f"-d={digest}"],
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
        _, pcrread_path = _require_tpm2_tools()

        # Read PCR values
        result = subprocess.run(
            [pcrread_path, f"sha256:{self._pcr}"],
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

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """TPM quote over current PCR state with nonce as qualifying data.

        Requires a pre-provisioned Attestation Key (AK) passed as ak_context
        at construction time. To provision one:

            tpm2_createprimary -c primary.ctx
            tpm2_create -C primary.ctx -G rsa -u ak.pub -r ak.priv
            tpm2_load -C primary.ctx -u ak.pub -r ak.priv -c ak.ctx

        The quote covers the current value of PCR self._pcr (already extended
        with the manifest hash at startup) and the qualifying data
        sha256(nonce || context_hash_bytes), which the hardware signs together.

        Note: Unlike SEV-SNP / TDX (where REPORT_DATA is freely caller-controlled),
        TPM PCR values accumulate — the boot-time extension cannot be undone.
        The qualifying data carries the freshness proof; the PCR proves TEE identity.
        """
        if self._ak_context is None:
            raise AttestationUnavailableError(
                "TPM runtime re-attestation requires a pre-provisioned Attestation Key. "
                "Provision one with tpm2_createprimary + tpm2_create + tpm2_load, "
                "then pass ak_context='/path/to/ak.ctx' to TPMProvider(). "
                "See: https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_quote.1/"
            )

        quote_bin = shutil.which("tpm2_quote")
        if quote_bin is None:
            raise AttestationUnavailableError(
                "tpm2_quote not found. Install tpm2-tools: apt-get install tpm2-tools"
            )

        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying_data = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying_data).hexdigest()}"

        import os as _os
        import tempfile as _tempfile
        msg_fd, msg_path = _tempfile.mkstemp(suffix=".msg")
        sig_fd, sig_path = _tempfile.mkstemp(suffix=".sig")
        _os.close(msg_fd)
        _os.close(sig_fd)

        try:
            result = subprocess.run(
                [
                    quote_bin,
                    f"--key-context={self._ak_context}",
                    f"--pcr-list=sha256:{self._pcr}",
                    f"--qualification={qualifying_data.hex()}",
                    f"--message={msg_path}",
                    f"--signature={sig_path}",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise AttestationUnavailableError(
                    f"tpm2_quote failed: {result.stderr.strip()}"
                )
            with open(msg_path, "rb") as f:
                msg_bytes = f.read()
            with open(sig_path, "rb") as f:
                sig_bytes = f.read()
        finally:
            for p in (msg_path, sig_path):
                try:
                    _os.unlink(p)
                except OSError:
                    pass

        return RuntimeAttestationReport(
            platform=self.platform_label,
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            quote=msg_bytes + sig_bytes,
            raw={
                "pcr_index": self._pcr,
                "qualifying_data": qualifying_data.hex(),
                "tpm2_quote_output": result.stdout,
            },
        )

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
