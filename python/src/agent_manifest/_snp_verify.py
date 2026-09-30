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
from typing import Any

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


# AMD Root Keys (ARK), one per SEV-SNP product line, as served by the AMD Key
# Distribution Service at https://kdsintf.amd.com/vcek/v1/<product>/cert_chain
# (the second certificate in that bundle; the vlek/v1 bundle carries the same
# ARK). Fetched 2026-09-30. Each is a self-signed RSA-4096 certificate whose
# RSASSA-PSS self-signature and signature over the KDS ASK were checked when
# it was recorded; tests/fixtures/amd_kds/ holds those KDS bundles so the check
# is repeatable offline.
#
# verify_vcek_chain() pins the chain's ARK to this set by default, the same way
# _tdx_verify pins the Intel SGX Root CA. Without a pinned root, a VCEK/ASK/ARK
# chain made from freshly generated keys verified exactly as well as AMD's
# (GHSA-cf88-228w-w58h). The SHA-256 of each certificate's DER is recorded
# alongside and re-checked at use, so an edit to the PEM text cannot silently
# change which root is trusted.
AMD_ARK_MILAN_PEM = b"""-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==
-----END CERTIFICATE-----
"""
AMD_ARK_GENOA_PEM = b"""-----BEGIN CERTIFICATE-----
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
/wMz1R1BHg==
-----END CERTIFICATE-----
"""
AMD_ARK_TURIN_PEM = b"""-----BEGIN CERTIFICATE-----
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
zpacMwFusA==
-----END CERTIFICATE-----
"""

# SHA-256 of each ARK certificate's DER encoding, keyed by KDS product name.
AMD_ARK_SHA256: dict[str, str] = {
    "Milan": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
    "Genoa": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
    "Turin": "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a",
}

_AMD_ARK_PEMS: dict[str, bytes] = {
    "Milan": AMD_ARK_MILAN_PEM,
    "Genoa": AMD_ARK_GENOA_PEM,
    "Turin": AMD_ARK_TURIN_PEM,
}


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
    ``cert_chain_pem`` is the KDS ``cert_chain`` blob (ASK then ARK).

    The chain's ARK public key must match a pinned root. By default that is one
    of AMD's published ARKs embedded in this module (Milan, Genoa, Turin; see
    :data:`AMD_ARK_SHA256`). ``trusted_ark_der`` replaces that set with a single
    caller-chosen root. Before 0.14.0 an omitted ``trusted_ark_der`` meant no
    pin at all, so a chain built from freshly generated keys verified
    (GHSA-cf88-228w-w58h).

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

    def _spki(cert: x509.Certificate) -> bytes:
        return cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    chain_spki = _spki(ark)
    if trusted_ark_der is not None:
        # An explicit root replaces the embedded AMD set: it is how a caller
        # pins one product line, or a test chain, and nothing else is trusted.
        try:
            pinned_roots = [x509.load_der_x509_certificate(trusted_ark_der)]
        except ValueError as e:
            raise SnpVerificationError(f"trusted_ark_der is not a DER certificate: {e}") from e
    else:
        pinned_roots = amd_ark_certificates()
    if not any(hmac.compare_digest(chain_spki, _spki(root)) for root in pinned_roots):
        raise SnpVerificationError(
            "chain ARK does not match the pinned AMD root"
            if trusted_ark_der is not None
            else "chain ARK is not one of AMD's published ARKs (Milan, Genoa, "
            "Turin); pass trusted_ark_der to pin a different root"
        )

    return True


def amd_ark_certificates() -> list[Any]:
    """Return the embedded AMD ARK certificates, each checked against its pin.

    The PEM constants above are loaded and the SHA-256 of each DER encoding is
    compared with :data:`AMD_ARK_SHA256`. A mismatch raises
    :class:`SnpVerificationError` rather than trusting whatever the constant
    now holds.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError as e:  # pragma: no cover
        raise SnpVerificationError(
            "AMD root pinning requires the 'cryptography' package"
        ) from e

    roots: list[Any] = []
    for product, pem in _AMD_ARK_PEMS.items():
        cert = x509.load_pem_x509_certificate(pem)
        der = cert.public_bytes(serialization.Encoding.DER)
        if not hmac.compare_digest(
            hashlib.sha256(der).hexdigest(), AMD_ARK_SHA256[product]
        ):
            raise SnpVerificationError(
                f"embedded AMD ARK for {product} does not match its recorded SHA-256"
            )
        roots.append(cert)
    return roots


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
