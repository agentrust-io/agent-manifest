"""provider='auto' attestation backend selection.

Auto-selection order (first locally-verifiable silicon wins):
  1. AzureCVMProvider — if the Azure vTPM HCL NV index is present (paravisor
                        SNP; no /dev/sev-guest). Checked first because Azure
                        also exposes the configfs-TSM dir but with no provider.
  2. SEVSNPProvider  — if the sev-guest driver is loaded (/sys/module/sev_guest)
                        and the configfs-TSM interface is present (bare-metal /
                        non-paravisor SNP guest)
  3. TDXProvider     — if /dev/tdx-guest exists
  4. TPMProvider     — if tpm2_extend is in PATH
  5. SoftwareProvider — fallback, Level 0 only (no hardware attestation)

OPAQUEProvider is explicit opt-in: selected only when OPAQUE_ATTESTATION_URL
is set. It is never auto-detected.

The SoftwareProvider is never selected automatically for Level 1+ contexts.
Callers that require Level 1+ MUST explicitly check provider.level >= 1.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from typing import Any, cast

from ._providers import (
    AttestationProvider,
    AttestationReport,
    AttestationUnavailableError,
    RuntimeAttestationReport,
    TPMProvider,
)

_TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"


def _is_azure_cvm() -> bool:
    """True if the Azure confidential-VM vTPM HCL report index is readable.

    Cheap, non-raising probe: Azure exposes the SNP/HCL report at vTPM NV index
    0x01400001. This is absent on bare-metal SNP and on non-confidential VMs.
    """
    import subprocess

    exe = shutil.which("tpm2_nvreadpublic")
    if exe is None:
        return False
    try:
        proc = subprocess.run(
            [exe, "0x01400001"], capture_output=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return proc.returncode == 0


class SoftwareProvider(AttestationProvider):
    """Level 0 software-only fallback — no hardware attestation.

    Produces a manifest hash using pure software SHA-256. Suitable for
    development and staging. MUST NOT be used for Level 1+ conformance.
    """

    LEVEL = 0

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        # No hardware to extend into — record the hash for report generation
        self._manifest_hash = self.manifest_hash_value(manifest_json)

    def get_attestation_report(self) -> AttestationReport:
        if not hasattr(self, "_manifest_hash"):
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        return AttestationReport(platform="software", manifest_hash=self._manifest_hash)

    def verify_manifest_in_report(self, report: AttestationReport, manifest_json: dict[str, Any]) -> bool:
        return bool(report.manifest_hash == self.manifest_hash_value(manifest_json))

    def attest_runtime_state(self, nonce: bytes, context_hash: str) -> RuntimeAttestationReport:
        """Software-only runtime state binding — no hardware involved.

        Useful for development and testing. MUST NOT be used to satisfy
        Level 1+ conformance claims because there is no hardware signing.
        """
        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        return RuntimeAttestationReport(
            platform="software",
            report_data_hash=f"sha256:{hashlib.sha256(qualifying).hexdigest()}",
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            raw={"warning": "software-only: not hardware attested, not valid for Level 1+"},
        )


def select_provider(level: int = 0) -> AttestationProvider:
    """Return the best available attestation provider for *level*.

    Args:
        level: Minimum conformance level required (0-3).

    Raises:
        AttestationUnavailableError: If *level* > 0 and no hardware provider
            is available.
    """
    # OPAQUE managed runtime — explicit opt-in only, not auto-detected
    if os.environ.get("OPAQUE_ATTESTATION_URL"):
        from ._hw_providers import OPAQUEProvider
        return cast(AttestationProvider, OPAQUEProvider())

    # Azure confidential VM (paravisor SNP, vTPM-rooted). Checked before the
    # bare-metal SNP probe because Azure also exposes the configfs-TSM dir but
    # registers no provider there.
    if _is_azure_cvm():
        from ._hw_providers import AzureCVMProvider
        return cast(AttestationProvider, AzureCVMProvider())

    # Bare-metal / non-paravisor AMD SEV-SNP via configfs-TSM. Gate on the
    # loaded sev-guest driver, not merely the configfs dir: the tsm report dir
    # exists whenever tsm.ko is present (e.g. on ordinary CI runners) even with
    # no provider registered, so dir-existence alone is not proof of an SNP guest.
    if os.path.exists("/sys/module/sev_guest") and os.path.isdir(_TSM_REPORT_DIR):
        from ._hw_providers import SEVSNPProvider
        return cast(AttestationProvider, SEVSNPProvider())

    # Intel TDX (non-paravisor) via configfs-TSM. Gate on the loaded tdx-guest
    # driver (the real device node is /dev/tdx_guest, underscore) so the empty
    # tsm dir on ordinary runners is not mistaken for a TDX guest.
    if (os.path.exists("/sys/module/tdx_guest") or os.path.exists("/dev/tdx_guest")) \
            and os.path.isdir(_TSM_REPORT_DIR):
        from ._hw_providers import TDXProvider
        return cast(AttestationProvider, TDXProvider())

    # Generic TPM / AWS Nitro
    if shutil.which("tpm2_extend"):
        return TPMProvider()

    # Software fallback
    if level >= 1:
        raise AttestationUnavailableError(
            "No hardware attestation provider available. "
            "Level 1+ conformance requires TPM 2.0, AMD SEV-SNP, or Intel TDX. "
            "To use the OPAQUE managed runtime, set OPAQUE_ATTESTATION_URL. "
            "For development use, set level=0 explicitly."
        )
    return SoftwareProvider()
