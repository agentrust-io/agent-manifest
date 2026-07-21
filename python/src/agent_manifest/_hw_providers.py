"""AMD SEV-SNP, Azure confidential VM, Intel TDX, and TEE attestation providers.

Pick a provider by deployment environment (``select_provider`` in
``_auto_provider.py`` does this automatically):

* :class:`AzureCVMProvider` — Azure confidential VMs (DCasv5/ECasv5 etc.).
  **Hardware-validated on live Azure SEV-SNP silicon.** Azure runs SNP behind a
  Hyper-V paravisor, so there is no ``/dev/sev-guest``; the SNP report is read
  from the vTPM NV index ``0x01400001`` (an "HCLA" wrapper) and the guest does
  NOT control ``REPORT_DATA`` (the paravisor binds the vTPM AK there). The
  manifest hash is therefore bound through the vTPM: it is extended into a PCR
  and covered by an AK-signed quote, and the AK is rooted in silicon by the SNP
  report + VCEK chain. This is the correct provider for Azure.

* :class:`SEVSNPProvider` — bare-metal / non-paravisor SNP guests that expose
  the report directly through the kernel configfs-TSM interface
  (``/sys/kernel/config/tsm/report``, kernel 6.7+), where the guest DOES control
  ``REPORT_DATA``. Hardware-validated end to end on a non-paravisor SEV-SNP guest
  (GCP N2D, AMD Milan). On Azure use :class:`AzureCVMProvider` instead. (The
  previous ``/dev/sev-guest`` ioctl implementation was incorrect and has been
  removed — see #204/#205.)

* :class:`TDXProvider` — Intel TDX. **Hardware-validated on a non-paravisor TDX
  guest (GCP C3).** Uses the configfs-TSM ``tdx_guest`` provider, which returns a
  full DCAP quote; quote signature + Intel PCK-chain verification live in
  ``_tdx_verify.py``. Azure TDX (paravisor/vTPM-rooted, like Azure SNP) is a
  separate follow-up.

* :class:`OPAQUEProvider` — OPAQUE managed runtime attestation (#8). NOT
  IMPLEMENTED: the managed service is not generally available and the SDK does
  not verify its TRACE claim, so the provider fails closed at construction.

Report parsing and the SNP signature/VCEK-chain verification live in
``_snp_verify.py`` and were validated against a report captured from real
SEV-SNP hardware.
"""
from __future__ import annotations

import hashlib
import os
from typing import Any, Optional

from ._providers import (
    AttestationProvider,
    AttestationReport,
    AttestationUnavailableError,
    RuntimeAttestationReport,
)


# ---------------------------------------------------------------------------
# AMD SEV-SNP Provider (bare-metal / configfs-TSM)
# ---------------------------------------------------------------------------

# Modern in-kernel attestation interface (kernel 6.7+): a configfs group where
# a caller writes up to 64 bytes of report data to `inblob` and reads the raw
# platform report from `outblob`. Supersedes the old /dev/sev-guest ioctl.
_TSM_REPORT_DIR = "/sys/kernel/config/tsm/report"
_TSM_ENTRY = "agent-manifest"


def _tsm_get_report(report_data: bytes) -> tuple[bytes, str, Optional[bytes]]:
    """Fetch a raw platform report from the kernel configfs-TSM interface.

    Writes *report_data* (<=64 bytes) to a fresh report entry's ``inblob`` and
    reads back ``outblob`` (the raw report), ``provider`` (e.g. "sev_guest"),
    and ``auxblob`` (certificate chain, when the provider supplies one).

    Requires root and a TEE guest whose driver has registered a TSM report
    provider. Returns ``(outblob, provider, auxblob_or_None)``.
    """
    if not os.path.isdir(_TSM_REPORT_DIR):
        raise AttestationUnavailableError(
            f"configfs-TSM report interface not present at {_TSM_REPORT_DIR}. "
            "Requires kernel 6.7+ with a registered TSM provider (e.g. the "
            "sev-guest driver on a bare-metal SNP guest). On Azure confidential "
            "VMs use AzureCVMProvider instead."
        )
    entry = os.path.join(_TSM_REPORT_DIR, _TSM_ENTRY)
    try:
        os.mkdir(entry)
    except FileExistsError:
        pass
    except OSError as e:
        raise AttestationUnavailableError(
            f"could not create TSM report entry {entry}: {e}. "
            "No TSM provider is registered (is this really an SNP guest, and are "
            "you root?). On Azure use AzureCVMProvider."
        ) from e
    try:
        with open(os.path.join(entry, "inblob"), "wb") as f:
            f.write(report_data)
        with open(os.path.join(entry, "outblob"), "rb") as f:
            outblob = f.read()
        with open(os.path.join(entry, "provider")) as f:
            provider = f.read().strip()
        auxblob: Optional[bytes] = None
        try:
            with open(os.path.join(entry, "auxblob"), "rb") as f:
                aux = f.read()
            auxblob = aux or None
        except OSError:
            auxblob = None
    finally:
        try:
            os.rmdir(entry)
        except OSError:
            pass
    return outblob, provider, auxblob


class SEVSNPProvider(AttestationProvider):
    """AMD SEV-SNP attestation via the kernel configfs-TSM interface.

    For **bare-metal / non-paravisor SNP guests** (kernel 6.7+) where the guest
    controls ``REPORT_DATA``. Binds the manifest hash into ``REPORT_DATA``: the
    first 32 bytes carry ``sha256(manifest_pre_image)``, the rest is zero.

    Report parsing and signature verification use :mod:`._snp_verify`, which was
    validated against a real SNP report. **Hardware-validated end to end on a
    non-paravisor SEV-SNP guest (GCP N2D, AMD Milan):** the manifest digest lands
    in the guest-controlled ``REPORT_DATA`` and the report verifies against the
    AMD VCEK chain. On Azure confidential VMs use :class:`AzureCVMProvider`
    instead (the guest cannot set ``REPORT_DATA`` there — the paravisor binds the
    vTPM AK into it).

    Requirements:
      - AMD EPYC (Milan or later) SNP guest, kernel 6.7+ with sev-guest driver
      - ``/sys/kernel/config/tsm/report`` present and a registered provider
      - root (configfs writes)

    Args:
        require_vcek_verification: when True, fetch the VCEK from the AMD KDS at
            report time and verify the report signature + chain; a failure
            raises. Requires network and the ``httpx`` extra.
        product: AMD product line for KDS lookups ("Milan", "Genoa", "Turin").
    """

    def __init__(
        self,
        require_vcek_verification: bool = False,
        product: str = "Milan",
    ) -> None:
        if not os.path.isdir(_TSM_REPORT_DIR):
            raise AttestationUnavailableError(
                f"AMD SEV-SNP configfs-TSM interface not found at {_TSM_REPORT_DIR}. "
                "Requires a bare-metal SNP guest (kernel 6.7+). On Azure use "
                "AzureCVMProvider."
            )
        self._require_vcek = require_vcek_verification
        self._product = product
        self._manifest_hash: Optional[str] = None
        self._report_bytes: Optional[bytes] = None

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Request an SNP report with REPORT_DATA = sha256(pre_image) || 0x00*32."""
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).digest()
        self._manifest_hash = f"sha256:{digest.hex()}"
        outblob, provider, _aux = _tsm_get_report(digest + bytes(32))
        if provider and provider != "sev_guest":
            raise AttestationUnavailableError(
                f"TSM provider is {provider!r}, not 'sev_guest'; wrong platform "
                "for SEVSNPProvider."
            )
        self._report_bytes = outblob

    def _report_or_raise(self) -> bytes:
        if self._report_bytes is None:
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        return self._report_bytes

    def get_attestation_report(self) -> AttestationReport:
        from ._snp_verify import parse_snp_report

        raw = self._report_or_raise()
        rep = parse_snp_report(raw)
        vcek_verified = False
        if self._require_vcek:
            from ._snp_verify import (
                fetch_vcek,
                verify_snp_signature,
                verify_vcek_chain,
            )
            vcek_der, chain_pem = fetch_vcek(self._product, rep)
            if not verify_snp_signature(rep, vcek_der):
                raise AttestationUnavailableError(
                    "SNP report signature did not verify against the fetched VCEK."
                )
            verify_vcek_chain(vcek_der, chain_pem)
            vcek_verified = True
        return AttestationReport(
            platform="amd-sev-snp",
            manifest_hash=self._manifest_hash or "",
            quote=rep.raw,  # raw SNP report — verify_attestation_chain reads this
            raw={
                "report_data": rep.report_data.hex(),
                "measurement": rep.measurement.hex(),
                "vcek_cert_chain_verified": vcek_verified,
            },
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        import hmac as _hmac
        expected_hex = self.manifest_hash_value(manifest_json).split(":", 1)[-1]
        if self._report_bytes is not None:
            from ._snp_verify import parse_snp_report
            actual = parse_snp_report(self._report_bytes).report_data[:32].hex()
            return _hmac.compare_digest(actual, expected_hex)
        return report.manifest_hash == self.manifest_hash_value(manifest_json)

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Fresh SNP report with REPORT_DATA = sha256(nonce || context_hash_bytes)."""
        from ._snp_verify import parse_snp_report

        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying).hexdigest()}"
        outblob, _provider, _aux = _tsm_get_report(qualifying + bytes(32))
        rep = parse_snp_report(outblob)
        return RuntimeAttestationReport(
            platform="amd-sev-snp",
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            quote=rep.raw,
            raw={
                "report_data": rep.report_data.hex(),
                "measurement": rep.measurement.hex(),
                "vcek_cert_chain_verified": False,
            },
        )


# ---------------------------------------------------------------------------
# Azure Confidential VM Provider (vTPM-rooted SEV-SNP) — hardware-validated
# ---------------------------------------------------------------------------

# Azure vTPM NV index holding the "HCLA" report (SNP report + runtime data).
_AZURE_HCL_NV_INDEX = "0x01400001"
# Default resettable, application-scope PCR for the manifest measurement.
_AZURE_MANIFEST_PCR = 16


def _run_tpm(args: list[str]) -> bytes:
    """Run a tpm2-tools command, returning stdout bytes or raising."""
    import shutil
    import subprocess

    exe = shutil.which(args[0])
    if exe is None:
        raise AttestationUnavailableError(
            f"{args[0]} not found. Install tpm2-tools: apt-get install tpm2-tools"
        )
    proc = subprocess.run([exe, *args[1:]], capture_output=True)
    if proc.returncode != 0:
        raise AttestationUnavailableError(
            f"{' '.join(args)} failed: {proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


class AzureCVMProvider(AttestationProvider):
    """Azure confidential VM attestation — hardware-validated on SEV-SNP silicon.

    Azure runs SEV-SNP behind a Hyper-V paravisor, so there is no
    ``/dev/sev-guest`` and the guest cannot set ``REPORT_DATA`` (the paravisor
    binds the vTPM attestation key into it). This provider therefore roots the
    manifest binding in the **vTPM**:

      1. ``extend_manifest_hash`` extends ``sha256(manifest_pre_image)`` into a
         vTPM PCR (default PCR 16).
      2. ``get_attestation_report`` reads the SNP/HCL report from vTPM NV index
         ``0x01400001``, confirms ``REPORT_DATA == sha256(runtime_data)`` (the
         Azure binding of the vTPM AK to the silicon), and produces an
         AK-signed quote over the manifest PCR.

    A verifier can then chain: manifest hash -> PCR -> AK quote -> AK bound in
    SNP ``REPORT_DATA`` -> SNP report signed by VCEK -> VCEK<-ASK<-ARK. Every
    link was validated on a live Azure SEV-SNP VM.

    Requirements:
      - Azure confidential VM (e.g. DCasv5) with vTPM enabled
      - tpm2-tools installed; read access to the vTPM (root, or tss group)

    Args:
        pcr_index: PCR to extend the manifest hash into (default 16).
        product: AMD product line for VCEK lookups ("Milan", "Genoa", "Turin").
    """

    def __init__(self, pcr_index: int = _AZURE_MANIFEST_PCR, product: str = "Milan") -> None:
        # Confirm the Azure HCL NV index is present; this is the signal that we
        # are on an Azure confidential VM with the paravisor attestation surface.
        try:
            _run_tpm(["tpm2_nvreadpublic", _AZURE_HCL_NV_INDEX])
        except AttestationUnavailableError as e:
            raise AttestationUnavailableError(
                f"Azure confidential VM attestation unavailable: {e}"
            ) from e
        self._pcr = pcr_index
        self._product = product
        self._manifest_hash: Optional[str] = None

    @property
    def pcr_index(self) -> int:
        return self._pcr

    def _read_hcl_report(self) -> bytes:
        import os as _os
        import tempfile as _tempfile

        fd, path = _tempfile.mkstemp(suffix=".hcl")
        _os.close(fd)
        try:
            _run_tpm(["tpm2_nvread", _AZURE_HCL_NV_INDEX, "-C", "o", "-o", path])
            with open(path, "rb") as f:
                return f.read()
        finally:
            try:
                _os.unlink(path)
            except OSError:
                pass

    def _find_ak_handle(self, modulus_hex: str) -> str:
        """Return the persistent handle whose RSA modulus matches the HCL AK."""
        out = _run_tpm(["tpm2_getcap", "handles-persistent"]).decode()
        handles = [line.split()[-1] for line in out.splitlines() if "0x" in line]
        for h in handles:
            pub = _run_tpm(["tpm2_readpublic", "-c", h]).decode()
            for line in pub.splitlines():
                s = line.strip()
                if s.startswith("rsa:"):
                    mod = s.split(":", 1)[1].strip()
                    if mod.lower() == modulus_hex.lower():
                        return h
        raise AttestationUnavailableError(
            "vTPM AK (HCLAkPub) persistent handle not found; cannot bind a quote "
            "to the silicon-rooted attestation key."
        )

    def _ak_modulus_hex(self, runtime_data: bytes) -> str:
        import base64
        import json

        keys = json.loads(runtime_data).get("keys", [])
        ak = next((k for k in keys if k.get("kid") == "HCLAkPub"), None)
        if ak is None:
            raise AttestationUnavailableError(
                "runtime data does not carry the HCLAkPub attestation key."
            )
        n_b64 = ak["n"] + "=" * ((4 - len(ak["n"]) % 4) % 4)
        return base64.urlsafe_b64decode(n_b64).hex()

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).hexdigest()
        self._manifest_hash = f"sha256:{digest}"
        # Reset the (resettable) PCR to zero first so the measurement is
        # deterministic: after a single extend the PCR is exactly
        # sha256(0x00*32 || digest), which verify_manifest_in_report replays.
        # Without the reset a polluted PCR (prior extends) would never match.
        _run_tpm(["tpm2_pcrreset", str(self._pcr)])
        _run_tpm(["tpm2_pcrextend", f"{self._pcr}:sha256={digest}"])

    def _quote(self, nonce_hex: str) -> dict[str, str]:
        """Produce an AK-signed quote over the manifest PCR; return b64 blobs."""
        import base64
        import os as _os
        import tempfile as _tempfile

        hcl = self._read_hcl_report()
        from ._snp_verify import parse_hcl_report, parse_snp_report, verify_runtime_data_binding

        snp_raw, runtime = parse_hcl_report(hcl)
        rep = parse_snp_report(snp_raw)
        if not verify_runtime_data_binding(rep, runtime):
            raise AttestationUnavailableError(
                "Azure SNP REPORT_DATA does not bind the runtime data; the vTPM "
                "AK cannot be trusted as silicon-rooted."
            )
        ak_handle = self._find_ak_handle(self._ak_modulus_hex(runtime))

        tmp = _tempfile.mkdtemp()
        msg, sig, pcrs, akpub = (
            os.path.join(tmp, n) for n in ("q.msg", "q.sig", "q.pcrs", "ak.pem")
        )
        try:
            _run_tpm([
                "tpm2_quote", "-c", ak_handle, "-l", f"sha256:{self._pcr}",
                "-q", nonce_hex, "-m", msg, "-s", sig, "-o", pcrs, "-g", "sha256",
            ])
            _run_tpm(["tpm2_readpublic", "-c", ak_handle, "-f", "pem", "-o", akpub])
            blobs = {}
            for label, p in (("quote_msg", msg), ("quote_sig", sig), ("quote_pcrs", pcrs)):
                with open(p, "rb") as f:
                    blobs[label] = base64.b64encode(f.read()).decode()
            with open(akpub) as f:
                blobs["ak_pub_pem"] = f.read()
        finally:
            for p in (msg, sig, pcrs, akpub):
                try:
                    _os.unlink(p)
                except OSError:
                    pass
            try:
                _os.rmdir(tmp)
            except OSError:
                pass
        blobs["snp_report"] = snp_raw.hex()
        blobs["runtime_data"] = runtime.decode("utf-8", "replace")
        blobs["measurement"] = rep.measurement.hex()
        blobs["report_data"] = rep.report_data.hex()
        return blobs

    def get_attestation_report(self) -> AttestationReport:
        if self._manifest_hash is None:
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        # nonce 0 for the boot-time quote; attest_runtime_state uses a fresh nonce.
        blobs = self._quote("00" * 16)
        pcr_value = _run_tpm(["tpm2_pcrread", f"sha256:{self._pcr}"]).decode()
        snp_raw = bytes.fromhex(blobs["snp_report"])
        return AttestationReport(
            platform="azure-cvm-sev-snp",
            manifest_hash=self._manifest_hash,
            quote=snp_raw,  # raw SNP report so verify_attestation_chain can check it
            raw={
                "report_data": blobs["report_data"],
                "measurement": blobs["measurement"],
                "runtime_data_binding_verified": True,
                "ak_pub_pem": blobs["ak_pub_pem"],
                "pcr_index": self._pcr,
                "pcr_read": pcr_value,
                "quote_msg": blobs["quote_msg"],
                "quote_sig": blobs["quote_sig"],
                "quote_pcrs": blobs["quote_pcrs"],
                "vcek_cert_chain_verified": False,
            },
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        """Confirm the manifest PCR equals a single extension of the manifest hash.

        A resettable PCR starts at 0x00*32; after one extension its value is
        ``sha256(0x00*32 || manifest_digest)``. Matching that proves the
        manifest hash (and nothing else) was measured into the PCR.
        """
        import hmac as _hmac

        digest = self.manifest_hash_value(manifest_json).split(":", 1)[-1]
        expected = hashlib.sha256(bytes(32) + bytes.fromhex(digest)).hexdigest()
        pcr_read = (report.raw or {}).get("pcr_read", "")
        got = ""
        for line in pcr_read.splitlines():
            s = line.strip()
            if s.startswith(f"{self._pcr}:"):
                got = s.split(":", 1)[1].strip().lower().removeprefix("0x")
        return bool(got) and _hmac.compare_digest(got, expected)

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Fresh AK-signed quote over the manifest PCR with nonce as qualifying data.

        The nonce binds this quote to a verifier challenge; the immutable SNP
        report (and its VCEK chain) still roots the AK in silicon.
        """
        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying).hexdigest()}"
        blobs = self._quote(qualifying.hex())
        return RuntimeAttestationReport(
            platform="azure-cvm-sev-snp",
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            quote=bytes.fromhex(blobs["snp_report"]),
            raw={
                "measurement": blobs["measurement"],
                "ak_pub_pem": blobs["ak_pub_pem"],
                "quote_msg": blobs["quote_msg"],
                "quote_sig": blobs["quote_sig"],
                "quote_pcrs": blobs["quote_pcrs"],
                "qualifying_data": qualifying.hex(),
            },
        )


# ---------------------------------------------------------------------------
# Intel TDX Provider
# ---------------------------------------------------------------------------

_TDX_GUEST_DEV = "/dev/tdx_guest"  # note: underscore (the real device node)


class TDXProvider(AttestationProvider):
    """Intel TDX attestation via the kernel configfs-TSM interface.

    **Hardware-validated on a non-paravisor Intel TDX guest (GCP C3, kernel
    6.17).** On such a guest the configfs-TSM ``tdx_guest`` provider returns a
    full remotely-verifiable **DCAP quote** (v4, ECDSA-P256) with the PCK
    certificate chain embedded, not a bare local ``TDREPORT``. The guest
    controls ``REPORTDATA``, so the manifest hash is bound there: the first 32
    bytes carry ``sha256(manifest_pre_image)``, the rest is zero.

    Quote parsing and signature/PCK-chain verification live in
    :mod:`._tdx_verify` and were validated against a real TDX quote. Azure TDX
    (behind a Hyper-V paravisor, like Azure SNP) surfaces attestation through the
    vTPM instead and is a separate follow-up.

    Requirements:
      - Intel TDX trust domain, kernel 6.7+ with the tdx-guest driver and the
        configfs-TSM interface, and an in-guest quote-generation path (GCP C3)
      - ``/sys/kernel/config/tsm/report`` present with the ``tdx_guest`` provider
      - root (configfs writes)

    Args:
        require_quote_verification: when True, verify the DCAP quote signature +
            PCK chain (to the pinned Intel SGX Root CA) at report time; a failure
            raises.
    """

    def __init__(self, require_quote_verification: bool = False) -> None:
        if not os.path.isdir(_TSM_REPORT_DIR):
            raise AttestationUnavailableError(
                f"Intel TDX configfs-TSM interface not found at {_TSM_REPORT_DIR}. "
                "Requires a TDX guest (kernel 6.7+). On Azure use the vTPM-rooted "
                "path (Azure TDX support is a follow-up)."
            )
        self._require_quote = require_quote_verification
        self._manifest_hash: Optional[str] = None
        self._quote: Optional[bytes] = None

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        """Obtain a TDX quote with REPORTDATA = sha256(pre_image) || 0x00*32."""
        pre = self.manifest_pre_image(manifest_json)
        digest = hashlib.sha256(pre).digest()
        self._manifest_hash = f"sha256:{digest.hex()}"
        outblob, provider, _aux = _tsm_get_report(digest + bytes(32))
        if provider and provider != "tdx_guest":
            raise AttestationUnavailableError(
                f"TSM provider is {provider!r}, not 'tdx_guest'; wrong platform "
                "for TDXProvider."
            )
        self._quote = outblob

    def _quote_or_raise(self) -> bytes:
        if self._quote is None:
            raise AttestationUnavailableError(
                "Call extend_manifest_hash() before get_attestation_report()."
            )
        return self._quote

    def get_attestation_report(self) -> AttestationReport:
        from ._tdx_verify import parse_tdx_quote, verify_tdx_quote

        quote = self._quote_or_raise()
        parsed = parse_tdx_quote(quote)
        quote_verified = False
        if self._require_quote:
            if not verify_tdx_quote(quote):
                raise AttestationUnavailableError(
                    "TDX quote signature / PCK chain did not verify."
                )
            quote_verified = True
        return AttestationReport(
            platform="intel-tdx",
            manifest_hash=self._manifest_hash or "",
            quote=quote,  # full DCAP quote — verify_attestation_chain reads this
            raw={
                "report_data": parsed.report_data.hex(),
                "measurement": parsed.mrtd.hex(),
                "rtmrs": [r.hex() for r in parsed.rtmrs],
                "quote_verified": quote_verified,
            },
        )

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        import hmac as _hmac
        expected_hex = self.manifest_hash_value(manifest_json).split(":", 1)[-1]
        if self._quote is not None:
            from ._tdx_verify import parse_tdx_quote
            actual = parse_tdx_quote(self._quote).report_data[:32].hex()
            return _hmac.compare_digest(actual, expected_hex)
        return report.manifest_hash == self.manifest_hash_value(manifest_json)

    def attest_runtime_state(
        self,
        nonce: bytes,
        context_hash: str,
    ) -> RuntimeAttestationReport:
        """Fresh TDX quote with REPORTDATA = sha256(nonce || context_hash_bytes)."""
        from ._tdx_verify import parse_tdx_quote

        context_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
        qualifying = hashlib.sha256(nonce + context_bytes).digest()
        report_data_hash = f"sha256:{hashlib.sha256(qualifying).hexdigest()}"
        outblob, _provider, _aux = _tsm_get_report(qualifying + bytes(32))
        parsed = parse_tdx_quote(outblob)
        return RuntimeAttestationReport(
            platform="intel-tdx",
            report_data_hash=report_data_hash,
            context_hash=context_hash,
            nonce_hex=nonce.hex(),
            quote=outblob,
            raw={
                "report_data": parsed.report_data.hex(),
                "measurement": parsed.mrtd.hex(),
            },
        )



# ---------------------------------------------------------------------------
# OPAQUE Provider
# ---------------------------------------------------------------------------


class OPAQUEProvider(AttestationProvider):
    """OPAQUE managed runtime attestation — NOT IMPLEMENTED.

    The OPAQUE managed attestation service is not generally available, and the
    SDK does not verify the TRACE claim such a service would return (no claim
    signature check and no verification of the service's own enclave
    measurement). Rather than ship a path that looks like verification but is
    not (see issue #201 §5), this provider is explicitly disabled: constructing
    it raises AttestationUnavailableError.

    It will be implemented when the managed service is available and a real
    claim-verification path exists (signature verified against a pinned OPAQUE
    key, plus a service_measurement check per spec §3.3). Until then, use a
    locally-verifiable provider (SEV-SNP / TDX / Azure CVM) for Level 1+.
    """

    _NOT_IMPLEMENTED = (
        "OPAQUE managed runtime attestation is not implemented. The managed "
        "service is not generally available, and the SDK does not verify the "
        "returned TRACE claim's signature or the service's enclave measurement, "
        "so it must not be relied upon. Use a locally-verifiable provider "
        "(SEV-SNP / TDX / Azure CVM) for Level 1+ attestation."
    )

    def __init__(self) -> None:
        raise AttestationUnavailableError(self._NOT_IMPLEMENTED)

    def extend_manifest_hash(self, manifest_json: dict[str, Any]) -> None:
        raise NotImplementedError(self._NOT_IMPLEMENTED)

    def get_attestation_report(self) -> AttestationReport:
        raise NotImplementedError(self._NOT_IMPLEMENTED)

    def verify_manifest_in_report(
        self, report: AttestationReport, manifest_json: dict[str, Any]
    ) -> bool:
        raise NotImplementedError(self._NOT_IMPLEMENTED)

    def attest_runtime_state(
        self, nonce: bytes, context_hash: str
    ) -> RuntimeAttestationReport:
        raise NotImplementedError(self._NOT_IMPLEMENTED)
