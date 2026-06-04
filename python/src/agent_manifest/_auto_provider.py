"""provider='auto' attestation backend selection.

Selection order (first available wins):
  1. OPAQUEProvider  — if OPAQUE_ATTESTATION_URL env var is set
  2. SEVSNPProvider  — if /dev/sev-guest exists
  3. TDXProvider     — if /dev/tdx-guest exists
  4. TPMProvider     — if tpm2_extend is in PATH
  5. SoftwareProvider — fallback, Level 0 only (no hardware attestation)

The SoftwareProvider is never selected automatically for Level 1+ contexts.
Callers that require Level 1+ MUST explicitly check provider.level >= 1.
"""
from __future__ import annotations

import os
import shutil
from typing import Union

from ._providers import AttestationProvider, AttestationUnavailableError, TPMProvider


class SoftwareProvider(AttestationProvider):
    """Level 0 software-only fallback — no hardware attestation.

    Produces a manifest hash using pure software SHA-256. Suitable for
    development and staging. MUST NOT be used for Level 1+ conformance.
    """

    LEVEL = 0

    def extend_manifest_hash(self, manifest_json):
        # No hardware to extend into — record the hash for report generation
        self._manifest_hash = self.manifest_hash_value(manifest_json)

    def get_attestation_report(self):
        from ._providers import AttestationReport
        h = getattr(self, "_manifest_hash", "")
        return AttestationReport(platform="software", manifest_hash=h)

    def verify_manifest_in_report(self, report, manifest_json):
        return report.manifest_hash == self.manifest_hash_value(manifest_json)


def select_provider(level: int = 0) -> AttestationProvider:
    """Return the best available attestation provider for *level*.

    Args:
        level: Minimum conformance level required (0-3).

    Raises:
        AttestationUnavailableError: If *level* > 0 and no hardware provider
            is available.
    """
    # OPAQUE managed runtime
    if os.environ.get("OPAQUE_ATTESTATION_URL"):
        try:
            from ._opaque_provider import OPAQUEProvider  # type: ignore[import]
            return OPAQUEProvider()
        except ImportError:
            pass

    # AMD SEV-SNP
    if os.path.exists("/dev/sev-guest"):
        try:
            from ._sev_provider import SEVSNPProvider  # type: ignore[import]
            return SEVSNPProvider()
        except ImportError:
            pass

    # Intel TDX
    if os.path.exists("/dev/tdx-guest"):
        try:
            from ._tdx_provider import TDXProvider  # type: ignore[import]
            return TDXProvider()
        except ImportError:
            pass

    # Generic TPM / AWS Nitro
    if shutil.which("tpm2_extend"):
        return TPMProvider()

    # Software fallback
    if level >= 1:
        raise AttestationUnavailableError(
            "No hardware attestation provider available. "
            "Level 1+ conformance requires TPM 2.0, AMD SEV-SNP, Intel TDX, "
            "or the OPAQUE managed runtime. "
            "For development use, set level=0 explicitly."
        )
    return SoftwareProvider()
