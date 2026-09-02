"""AMD SEV-SNP attestation report parsing and signature-chain verification.

This module implements the hardware signature backend that ``_attestation.py``
was missing (issue #204, step 1). Every offset, algorithm, and chain step here
was validated against a genuine SEV-SNP report captured from an Azure
confidential VM (family 0x19 / model 0x01, "Milan"); see
``tests/vectors/snp/`` and ``tests/test_snp_verify.py``.

Two report shapes are handled:

* **Raw SNP attestation report** (1184 bytes) as defined by the AMD SEV-SNP
  ABI, Table 22. ``REPORT_DATA`` is at 0x50, ``MEASUREMENT`` at 0x90,
  ``REPORTED_TCB`` at 0x180, ``CHIP_ID`` at 0x1a0, and the ECDSA-P384
  signature at 0x2a0 over the report body ``report[:0x2a0]``.

* **Azure HCL report** ("HCLA" magic) as read from the vTPM NV index
  ``0x01400001`` on an Azure confidential VM. The raw SNP report is embedded at
  offset 0x20 and is followed by a runtime-data blob (JSON holding the vTPM
  attestation key). On Azure the guest does NOT control ``REPORT_DATA``: the
  paravisor sets it to ``sha256(runtime_data)`` to bind the vTPM AK to the
  silicon. :func:`verify_runtime_data_binding` checks exactly that relationship.

The trust chain, all steps validated on real hardware:

    manifest hash -> vTPM PCR -> AK-signed quote
        -> AK == HCLAkPub bound in SNP REPORT_DATA
        -> SNP report signed by VCEK
        -> VCEK <- ASK <- ARK (AMD root)

Certificate-chain and report-signature verification need the ``cryptography``
package. Fetching the VCEK from the AMD KDS additionally needs ``httpx`` and is
optional: a caller who already holds the VCEK + cert chain (e.g. from the
report's aux blob) can verify fully offline.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from datetime import datetime

# Raw SNP attestation report field offsets (AMD SEV-SNP ABI, Table 22).
_OFF_VERSION = 0x00
_OFF_GUEST_SVN = 0x04
_OFF_POLICY = 0x08
_OFF_VMPL = 0x30
_OFF_SIG_ALGO = 0x34
_OFF_PLATFORM_INFO = 0x40
_OFF_REPORT_DATA = 0x50
_OFF_MEASUREMENT = 0x90
_OFF_HOST_DATA = 0xC0
_OFF_REPORTED_TCB = 0x180
_OFF_CHIP_ID = 0x1A0
_OFF_SIGNATURE = 0x2A0
_SNP_REPORT_LEN = 0x4A0  # 1184 bytes

# ECDSA-P384 signature layout inside the report: r and s are little-endian,
# each right-padded to 72 bytes (AMD stores 48 significant bytes of each).
_SIG_COMPONENT_STRIDE = 72
_SIG_COMPONENT_BYTES = 48

# sig_algo values from the AMD SEV-SNP ABI. 1 is ECDSA P-384 with SHA-384, which
# is the only scheme AMD has defined; the field exists so a future one can be
# distinguished, which is exactly why it must be checked rather than assumed.
SIG_ALGO_ECDSA_P384_SHA384 = 1

# The ABI offsets, public because they are the contract consumers build and
# appraise reports against. Downstreams previously kept their own ctypes mirror
# of this layout purely to read offsets off it; four copies of one table is four
# chances for them to disagree, so the table is exported instead.
SNP_REPORT_LEN = _SNP_REPORT_LEN
SNP_OFFSETS: dict[str, int] = {
    "version": _OFF_VERSION,
    "guest_svn": _OFF_GUEST_SVN,
    "policy": _OFF_POLICY,
    "vmpl": _OFF_VMPL,
    "sig_algo": _OFF_SIG_ALGO,
    "platform_info": _OFF_PLATFORM_INFO,
    "report_data": _OFF_REPORT_DATA,
    "measurement": _OFF_MEASUREMENT,
    "host_data": _OFF_HOST_DATA,
    "reported_tcb": _OFF_REPORTED_TCB,
    "chip_id": _OFF_CHIP_ID,
    "signature": _OFF_SIGNATURE,
}

_HCL_MAGIC = b"HCLA"
_HCL_SNP_REPORT_OFFSET = 0x20


class SnpVerificationError(Exception):
    """Raised when an SNP report or its certificate chain fails verification."""


@dataclass
class SnpReport:
    """Parsed fields of a raw SEV-SNP attestation report."""

    version: int
    guest_svn: int
    policy: int
    vmpl: int
    signature_algo: int
    platform_info: int  # PLATFORM_INFO bitfield at 0x40, see SnpPlatformInfo
    report_data: bytes  # 64 bytes
    measurement: bytes  # 48 bytes
    host_data: bytes  # 32 bytes
    reported_tcb: bytes  # 8 bytes: [bl, tee, _, _, _, _, snp, ucode]
    chip_id: bytes  # 64 bytes
    signature: bytes  # 512 bytes (r||s padded)
    signed_body: bytes  # report[:0x2a0] — the bytes covered by the signature
    raw: bytes  # the full 1184-byte report

    @property
    def tcb_spls(self) -> dict[str, int]:
        """Security-patch levels used to address the VCEK on the AMD KDS."""
        t = self.reported_tcb
        return {"bl": t[0], "tee": t[1], "snp": t[6], "ucode": t[7]}


def parse_snp_report(report: bytes) -> SnpReport:
    """Parse a raw 1184-byte SEV-SNP attestation report."""
    if len(report) < _SNP_REPORT_LEN:
        raise SnpVerificationError(
            f"SNP report too short: {len(report)} bytes, need {_SNP_REPORT_LEN}"
        )
    return SnpReport(
        version=struct.unpack_from("<I", report, _OFF_VERSION)[0],
        guest_svn=struct.unpack_from("<I", report, _OFF_GUEST_SVN)[0],
        policy=struct.unpack_from("<Q", report, _OFF_POLICY)[0],
        vmpl=struct.unpack_from("<I", report, _OFF_VMPL)[0],
        signature_algo=struct.unpack_from("<I", report, _OFF_SIG_ALGO)[0],
        platform_info=struct.unpack_from("<Q", report, _OFF_PLATFORM_INFO)[0],
        report_data=report[_OFF_REPORT_DATA:_OFF_REPORT_DATA + 64],
        measurement=report[_OFF_MEASUREMENT:_OFF_MEASUREMENT + 48],
        host_data=report[_OFF_HOST_DATA:_OFF_HOST_DATA + 32],
        reported_tcb=report[_OFF_REPORTED_TCB:_OFF_REPORTED_TCB + 8],
        chip_id=report[_OFF_CHIP_ID:_OFF_CHIP_ID + 64],
        signature=report[_OFF_SIGNATURE:_OFF_SIGNATURE + 512],
        signed_body=report[:_OFF_SIGNATURE],
        raw=report[:_SNP_REPORT_LEN],
    )


# ---------------------------------------------------------------- PLATFORM_INFO
#
# PLATFORM_INFO (ABI Table 22, offset 0x40) reports the state of the machine the
# report came from, as opposed to the identity of the workload on it. Signature,
# certificate chain and measurement together establish authenticity and identity;
# none of them say anything about the platform. This is the part that does.
#
# The bit assignments below were read from google/go-sev-guest `abi/abi.go` at
# commit c930ed67bebfe7245c0309888ec185bd9ad35899 on 2026-08-20 and cross-checked
# against the AMD SEV-SNP ABI.

PLATFORM_INFO_BITS: dict[str, int] = {
    "smt_enabled": 0,
    "tsme_enabled": 1,
    "ecc_enabled": 2,
    "rapl_disabled": 3,
    "ciphertext_hiding_dram_enabled": 4,
    "alias_check_complete": 5,
    # bit 6 is reserved and MBZ
    "tio_enabled": 7,
}

_PLATFORM_INFO_RESERVED_MASK = ~sum(1 << b for b in PLATFORM_INFO_BITS.values()) & 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class SnpPlatformInfo:
    """Decoded PLATFORM_INFO bitfield.

    Every field is a plain statement about the platform, phrased so that the
    field name matches what a set bit means. ``rapl_disabled`` is true when RAPL
    is disabled, because that is what bit 3 means; it is deliberately not
    inverted into a ``rapl_enabled`` convenience, since a negative-sense field
    that silently flips is how policy mistakes get made.
    """

    smt_enabled: bool
    tsme_enabled: bool
    ecc_enabled: bool
    rapl_disabled: bool
    ciphertext_hiding_dram_enabled: bool
    alias_check_complete: bool
    tio_enabled: bool
    raw: int
    unrecognized_bits: int
    """Bits set in PLATFORM_INFO that this library does not know how to name.

    Not an error on its own, and deliberately surfaced rather than masked away:
    an unrecognized bit means the silicon is telling you something this code was
    not written to understand. :func:`appraise_platform_info` can be asked to
    reject on it.
    """


def parse_platform_info(platform_info: int) -> SnpPlatformInfo:
    """Decode the PLATFORM_INFO bitfield from a report."""
    return SnpPlatformInfo(
        **{name: bool(platform_info & (1 << bit)) for name, bit in PLATFORM_INFO_BITS.items()},
        raw=platform_info,
        unrecognized_bits=platform_info & _PLATFORM_INFO_RESERVED_MASK,
    )


def appraise_platform_info(
    info: SnpPlatformInfo,
    *,
    require: set[str] | None = None,
    forbid: set[str] | None = None,
    reject_unrecognized_bits: bool = False,
) -> None:
    """Appraise a decoded PLATFORM_INFO against an explicit policy.

    ``require`` names fields that MUST be true. ``forbid`` names fields that MUST
    be false. **The direction is in the argument name, never in the field name**,
    which is the entire point of this signature.

    That is a deliberate departure from the shape the reference verifier uses.
    ``google/go-sev-guest`` carries a single ``SnpPlatformInfo`` policy struct of
    booleans, documents it as "the maximum of acceptable PLATFORM_INFO data", and
    then enforces four of its seven fields as minimums instead. Setting
    ``AliasCheckComplete = true`` there does not permit the condition, it demands
    it. Filed as https://github.com/google/go-sev-guest/issues/195 on 2026-08-20.
    A caller of this function cannot make that mistake, because there is no single
    bag of booleans whose meaning depends on which field you happened to pick.

    Both arguments default to empty, so **calling this with no policy asserts
    nothing**. That is the same vacuous default the reference verifier has, and it
    is stated here rather than left to be discovered: appraisal is opt in, and a
    caller who wants a platform requirement has to name it.

    :raises SnpVerificationError: on the first unmet requirement.
    """
    require = set(require or ())
    forbid = set(forbid or ())

    unknown = (require | forbid) - set(PLATFORM_INFO_BITS)
    if unknown:
        raise SnpVerificationError(
            "unknown PLATFORM_INFO field(s) in policy: "
            + ", ".join(sorted(unknown))
            + "; known fields are "
            + ", ".join(sorted(PLATFORM_INFO_BITS))
        )
    both = require & forbid
    if both:
        raise SnpVerificationError(
            "PLATFORM_INFO policy both requires and forbids: " + ", ".join(sorted(both))
        )

    for field in sorted(require):
        if not getattr(info, field):
            raise SnpVerificationError(
                f"platform policy requires {field}, but the report reports it false "
                f"(PLATFORM_INFO=0x{info.raw:x})"
            )
    for field in sorted(forbid):
        if getattr(info, field):
            raise SnpVerificationError(
                f"platform policy forbids {field}, but the report reports it true "
                f"(PLATFORM_INFO=0x{info.raw:x})"
            )
    if reject_unrecognized_bits and info.unrecognized_bits:
        raise SnpVerificationError(
            f"PLATFORM_INFO carries bits this library cannot name: "
            f"0x{info.unrecognized_bits:x} (PLATFORM_INFO=0x{info.raw:x})"
        )


def parse_hcl_report(hcl: bytes) -> tuple[bytes, bytes]:
    """Split an Azure "HCLA" report into (raw_snp_report, runtime_data).

    The raw SNP report is embedded at offset 0x20. The runtime-data blob that
    follows is length-prefixed (u32) immediately after the report; some HCL
    revisions pad the JSON, so we fall back to brace-delimited extraction and
    verify the binding via :func:`verify_runtime_data_binding`.
    """
    if hcl[:4] != _HCL_MAGIC:
        raise SnpVerificationError(
            f"not an HCL report: magic is {hcl[:4]!r}, expected {_HCL_MAGIC!r}"
        )
    snp = hcl[_HCL_SNP_REPORT_OFFSET:_HCL_SNP_REPORT_OFFSET + _SNP_REPORT_LEN]
    tail = hcl[_HCL_SNP_REPORT_OFFSET + _SNP_REPORT_LEN:]

    runtime = b""
    if len(tail) >= 4:
        (declared,) = struct.unpack_from("<I", tail, 0)
        if 0 < declared <= len(tail) - 4:
            runtime = tail[4:4 + declared]
    # Length-prefixed data should already be exact JSON; if it does not look
    # like JSON, fall back to brace extraction over the tail.
    if not (runtime[:1] == b"{" and runtime.rstrip()[-1:] == b"}"):
        start = tail.find(b"{")
        end = tail.rfind(b"}")
        runtime = tail[start:end + 1] if start >= 0 and end > start else b""
    return snp, runtime


def verify_runtime_data_binding(report: SnpReport, runtime_data: bytes) -> bool:
    """Check the Azure binding ``REPORT_DATA[:32] == sha256(runtime_data)``.

    On Azure confidential VMs the paravisor sets the SNP ``REPORT_DATA`` to the
    SHA-256 of the runtime-data blob, cryptographically binding the vTPM
    attestation key (carried in that blob) to genuine SNP silicon. Callers use
    this to trust that the vTPM AK which signs manifest-hash quotes is rooted in
    hardware.
    """
    digest = hashlib.sha256(runtime_data).digest()
    return hmac.compare_digest(report.report_data[:32], digest)


def load_snp_cert_chain(pem_bundle: bytes) -> tuple[object, object, object]:
    """Split a PEM bundle into ``(vcek, ask, ark)`` certificates.

    The AMD KDS and most capture tooling hand out one concatenated PEM. The three
    are told apart by shape rather than by order, which varies: the VCEK is the
    only EC leaf, and of the two RSA certificates the self-signed one is the ARK.

    Raises :class:`SnpVerificationError` if the bundle is not a well-formed SNP
    chain, so a caller cannot proceed with two of the three.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError as e:  # pragma: no cover - exercised via install extra
        raise SnpVerificationError(
            "loading an SNP certificate chain requires the 'cryptography' package"
        ) from e

    try:
        certs = x509.load_pem_x509_certificates(pem_bundle)
    except Exception as exc:
        raise SnpVerificationError(f"could not parse the PEM bundle: {exc}") from exc

    vcek = next((c for c in certs if isinstance(c.public_key(), ec.EllipticCurvePublicKey)), None)
    rsa_certs = [c for c in certs if isinstance(c.public_key(), rsa.RSAPublicKey)]
    ark = next((c for c in rsa_certs if c.subject == c.issuer), None)
    ask = next((c for c in rsa_certs if c is not ark), None)

    if vcek is None or ask is None or ark is None:
        raise SnpVerificationError(
            "bundle must contain a VCEK (EC), an ASK and a self-signed ARK (RSA)"
        )
    return vcek, ask, ark


def verify_snp_signature(report: SnpReport, vcek_cert_der: bytes) -> bool:
    """Verify the report's ECDSA-P384 signature against the VCEK public key.

    The report's own ``sig_algo`` field is checked first. Verifying with
    ECDSA-P384/SHA-384 because that is what AMD defines today, without confirming
    the report says so, would silently appraise a report that declares something
    else under the wrong scheme. Both downstream copies of this check enforced it;
    this one did not, so it is enforced here now.

    Returns True on success; raises :class:`SnpVerificationError` if the
    ``cryptography`` package is unavailable or the report declares an unsupported
    algorithm. A wrong or tampered report returns False rather than raising.
    """
    try:
        from typing import cast

        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError as e:  # pragma: no cover - exercised via install extra
        raise SnpVerificationError(
            "SNP signature verification requires the 'cryptography' package"
        ) from e

    if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384:
        raise SnpVerificationError(
            f"unsupported SNP signature algorithm {report.signature_algo} "
            f"(expected {SIG_ALGO_ECDSA_P384_SHA384}, ECDSA-P384/SHA-384)"
        )

    vcek = x509.load_der_x509_certificate(vcek_cert_der)
    r = int.from_bytes(report.signature[0:_SIG_COMPONENT_BYTES], "little")
    s = int.from_bytes(
        report.signature[_SIG_COMPONENT_STRIDE:_SIG_COMPONENT_STRIDE + _SIG_COMPONENT_BYTES],
        "little",
    )
    der_sig = utils.encode_dss_signature(r, s)
    # The VCEK leaf carries an EC (P-384) key; narrow for the ECDSA overload.
    pub = cast(ec.EllipticCurvePublicKey, vcek.public_key())
    try:
        pub.verify(der_sig, report.signed_body, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False


def verify_vcek_chain(
    vcek_cert_der: bytes,
    cert_chain_pem: bytes,
    *,
    trusted_ark_der: bytes | None = None,
    verification_time: datetime | None = None,
) -> bool:
    """Verify VCEK <- ASK <- ARK, and that ARK is self-signed (the AMD root).

    The AMD KDS signs each link with RSASSA-PSS (MGF1-SHA384, 48-byte salt).
    ``cert_chain_pem`` is the KDS ``cert_chain`` blob (ASK then ARK). If
    ``trusted_ark_der`` is supplied, the chain's ARK public key must match it,
    pinning the root instead of trusting whatever the chain carries.

    Every certificate in the chain must be within its validity period (see
    :func:`._cert_chain.check_validity_period`); an expired VCEK, ASK, or ARK
    is rejected even if every signature in the chain is otherwise valid.

    Returns True on success; raises :class:`SnpVerificationError` on a broken
    chain or missing ``cryptography``.
    """
    try:
        import re
        from typing import cast

        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        from ._cert_chain import CertChainError, check_validity_period
    except ImportError as e:  # pragma: no cover
        raise SnpVerificationError(
            "VCEK chain verification requires the 'cryptography' package"
        ) from e

    pems = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        cert_chain_pem,
        re.DOTALL,
    )
    if len(pems) < 2:
        raise SnpVerificationError("cert_chain must contain ASK and ARK certificates")

    vcek = x509.load_der_x509_certificate(vcek_cert_der)
    ask = x509.load_pem_x509_certificate(pems[0])
    ark = x509.load_pem_x509_certificate(pems[1])

    try:
        check_validity_period(vcek, label="VCEK", verification_time=verification_time)
        check_validity_period(ask, label="ASK", verification_time=verification_time)
        check_validity_period(ark, label="ARK", verification_time=verification_time)
    except CertChainError as e:
        raise SnpVerificationError(str(e)) from e

    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)

    def _check(child: x509.Certificate, issuer: x509.Certificate, label: str) -> None:
        # AMD's ASK/ARK are RSA keys; narrow for the RSASSA-PSS verify overload.
        issuer_pub = cast(RSAPublicKey, issuer.public_key())
        try:
            issuer_pub.verify(
                child.signature, child.tbs_certificate_bytes, pss, hashes.SHA384()
            )
        except InvalidSignature as e:
            raise SnpVerificationError(f"{label} signature invalid") from e

    _check(vcek, ask, "VCEK<-ASK")
    _check(ask, ark, "ASK<-ARK")
    _check(ark, ark, "ARK self-signature")  # AMD root is self-signed

    if trusted_ark_der is not None:
        pinned = x509.load_der_x509_certificate(trusted_ark_der)
        chain_spki = ark.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        pinned_spki = pinned.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not hmac.compare_digest(chain_spki, pinned_spki):
            raise SnpVerificationError("chain ARK does not match the pinned AMD root")

    return True


# AMD Key Distribution Service. Product names: "Milan", "Genoa", "Turin".
_KDS_BASE = "https://kdsintf.amd.com/vcek/v1"


def fetch_vcek(product: str, report: SnpReport) -> tuple[bytes, bytes]:
    """Fetch (vcek_der, cert_chain_pem) for *report* from the AMD KDS.

    Network convenience only; verification itself is offline. Requires httpx.
    """
    try:
        import httpx
    except ImportError as e:  # pragma: no cover
        raise SnpVerificationError(
            'fetch_vcek requires httpx: pip install "agent-manifest[server]"'
        ) from e

    spl = report.tcb_spls
    chip = report.chip_id.hex()
    url = (
        f"{_KDS_BASE}/{product}/{chip}"
        f"?blSPL={spl['bl']}&teeSPL={spl['tee']}&snpSPL={spl['snp']}&ucodeSPL={spl['ucode']}"
    )
    with httpx.Client(timeout=30.0) as client:
        vcek = client.get(url)
        vcek.raise_for_status()
        chain = client.get(f"{_KDS_BASE}/{product}/cert_chain")
        chain.raise_for_status()
    return vcek.content, chain.content
