"""provider='auto' attestation backend selection.

Auto-selection order (first locally-verifiable silicon wins):
  1. SEVSNPProvider  — if /dev/sev-guest exists
  2. TDXProvider     — if /dev/tdx-guest exists
  3. TPMProvider     — if tpm2_extend is in PATH
  4. SoftwareProvider — fallback, Level 0 only (no hardware attestation)

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

    # AMD SEV-SNP
    if os.path.exists("/dev/sev-guest"):
        from ._hw_providers import SEVSNPProvider
        return cast(AttestationProvider, SEVSNPProvider())

    # Intel TDX
    if os.path.exists("/dev/tdx-guest"):
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
