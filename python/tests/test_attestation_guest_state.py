"""verify_attestation_chain refuses debug guests and non-VMPL0 SNP reports.

A debug-enabled guest (SEV-SNP guest policy DEBUG, bit 19; TDX
TDATTRIBUTES.DEBUG, bit 0) lets the host read and write guest memory, so the
REPORT_DATA it signs and the code that chose it are the host's to set. Before
this check, a genuine debug report with an allow-listed measurement returned
``passed=True``. Every report below carries a signature that verifies; the
only variable is the signed guest state.
"""
import hashlib
import os
import sys

import pytest

pytest.importorskip("cryptography")

from agent_manifest._attestation import (  # noqa: E402
    SignatureStatus,
    verify_attestation_chain,
    verify_runtime_quote,
)
from agent_manifest._providers import (  # noqa: E402
    AttestationReport,
    RuntimeAttestationReport,
)
from agent_manifest._snp_verify import (  # noqa: E402
    SNP_POLICY_DEBUG,
    parse_snp_report,
)
from agent_manifest._tdx_verify import TDX_TD_ATTR_DEBUG, parse_tdx_quote  # noqa: E402

from ._snp_synthetic import (  # noqa: E402
    ark_der_from_chain,
    build_synthetic_snp_report_with_chain,
)
from .test_attestation_chain import (  # noqa: E402
    _azure_good_fixture,
    _azure_report_from_fixture,
)

sys.path.insert(0, os.path.dirname(__file__))
from test_tdx_verify import _build_quote  # noqa: E402

DIGEST = hashlib.sha256(b"manifest-pre-image").hexdigest()
MANIFEST_HASH = f"sha256:{DIGEST}"
MEASUREMENT = "ab" * 48
MRTD = "11" * 48  # _build_quote's default MRTD

# What a real SNP guest sets without debug: ABI minor/major, SMT (16) and the
# must-be-one reserved bit 17. The committed Azure capture in the WCM repo
# reads 0x3001f.
_PRODUCTION_POLICY = 0x3001F


def _snp(policy: int = _PRODUCTION_POLICY, vmpl: int = 0, **kwargs):
    snp, vcek_der, chain = build_synthetic_snp_report_with_chain(
        DIGEST, MEASUREMENT, policy=policy, vmpl=vmpl
    )
    report = AttestationReport(
        platform="amd-sev-snp",
        manifest_hash=MANIFEST_HASH,
        quote=snp,
        raw={"report_data": DIGEST + "00" * 32, "measurement": MEASUREMENT},
    )
    return verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        expected_measurements={MEASUREMENT},
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
        trusted_ark_der=ark_der_from_chain(chain),
        **kwargs,
    )


def _tdx(td_attributes: int = 0, **kwargs):
    quote, root_pem = _build_quote(bytes.fromhex(DIGEST), td_attributes=td_attributes)
    report = AttestationReport(
        platform="intel-tdx",
        manifest_hash=MANIFEST_HASH,
        quote=quote,
        raw={"report_data": DIGEST + "00" * 32, "measurement": MRTD},
    )
    return verify_attestation_chain(
        report,
        expected_manifest_hash=MANIFEST_HASH,
        expected_measurements={MRTD},
        trusted_tdx_root_pem=root_pem,
        **kwargs,
    )


# --- SEV-SNP ---------------------------------------------------------------


def test_snp_policy_debug_is_bit_19():
    assert SNP_POLICY_DEBUG == 0x80000
    snp, _, _ = build_synthetic_snp_report_with_chain(
        DIGEST, MEASUREMENT, policy=_PRODUCTION_POLICY | SNP_POLICY_DEBUG
    )
    assert parse_snp_report(snp).debug is True
    snp, _, _ = build_synthetic_snp_report_with_chain(
        DIGEST, MEASUREMENT, policy=_PRODUCTION_POLICY
    )
    assert parse_snp_report(snp).debug is False


def test_snp_non_debug_vmpl0_passes_and_records_state():
    result = _snp()
    assert result.signature is SignatureStatus.VERIFIED
    assert result.measurement_matched is True
    assert result.passed is True
    assert result.debug is False
    assert result.vmpl == 0


def test_snp_debug_guest_with_allow_listed_measurement_fails():
    result = _snp(policy=_PRODUCTION_POLICY | SNP_POLICY_DEBUG)
    # Everything else about the report checks out; only the policy differs.
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is True
    assert result.measurement_matched is True
    assert result.debug is True
    assert result.passed is False
    assert any("debug-enabled" in r for r in result.reasons)


def test_snp_debug_guest_passes_only_with_explicit_opt_in():
    result = _snp(policy=_PRODUCTION_POLICY | SNP_POLICY_DEBUG, allow_debug=True)
    assert result.passed is True
    assert result.debug is True
    assert any("allow_debug=True" in r for r in result.reasons)


@pytest.mark.parametrize("vmpl", [1, 2, 3])
def test_snp_report_not_at_vmpl0_fails(vmpl):
    result = _snp(vmpl=vmpl)
    assert result.signature is SignatureStatus.VERIFIED
    assert result.vmpl == vmpl
    assert result.passed is False
    assert any(f"VMPL{vmpl}" in r for r in result.reasons)


def test_allow_debug_does_not_relax_vmpl():
    result = _snp(policy=_PRODUCTION_POLICY | SNP_POLICY_DEBUG, vmpl=2, allow_debug=True)
    assert result.passed is False


def test_debug_state_is_none_without_a_verified_signature():
    snp, _, chain = build_synthetic_snp_report_with_chain(
        DIGEST, MEASUREMENT, policy=_PRODUCTION_POLICY | SNP_POLICY_DEBUG
    )
    report = AttestationReport(
        platform="amd-sev-snp",
        manifest_hash=MANIFEST_HASH,
        quote=snp,
        raw={"report_data": DIGEST + "00" * 32},
    )
    result = verify_attestation_chain(report, expected_manifest_hash=MANIFEST_HASH)
    assert result.signature is SignatureStatus.NOT_IMPLEMENTED
    assert result.debug is None
    assert result.vmpl is None
    assert result.passed is False


def test_azure_debug_guest_fails_even_with_full_composite_binding():
    fx = _azure_good_fixture(snp_policy=_PRODUCTION_POLICY | SNP_POLICY_DEBUG)
    result = verify_attestation_chain(
        _azure_report_from_fixture(fx),
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=fx["vcek_der"],
        cert_chain_pem=fx["chain"],
        trusted_ark_der=ark_der_from_chain(fx["chain"]),
    )
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is True
    assert result.debug is True
    assert result.passed is False


def test_azure_non_debug_guest_still_passes():
    fx = _azure_good_fixture(snp_policy=_PRODUCTION_POLICY)
    result = verify_attestation_chain(
        _azure_report_from_fixture(fx),
        expected_manifest_hash=MANIFEST_HASH,
        vcek_cert_der=fx["vcek_der"],
        cert_chain_pem=fx["chain"],
        trusted_ark_der=ark_der_from_chain(fx["chain"]),
    )
    assert result.passed is True
    assert result.debug is False
    assert result.vmpl == 0


# --- Intel TDX -------------------------------------------------------------


def test_tdx_non_debug_passes_and_records_state():
    result = _tdx(td_attributes=1 << 28)  # SEPT_VE_DISABLE, as real TDs set
    assert result.signature is SignatureStatus.VERIFIED
    assert result.measurement_matched is True
    assert result.passed is True
    assert result.debug is False
    assert result.vmpl is None


def test_tdx_debug_td_with_allow_listed_mrtd_fails():
    result = _tdx(td_attributes=TDX_TD_ATTR_DEBUG | (1 << 28))
    assert result.signature is SignatureStatus.VERIFIED
    assert result.report_data_matched is True
    assert result.measurement_matched is True
    assert result.debug is True
    assert result.passed is False
    assert any("debug-enabled" in r for r in result.reasons)


def test_tdx_debug_td_passes_only_with_explicit_opt_in():
    result = _tdx(td_attributes=TDX_TD_ATTR_DEBUG, allow_debug=True)
    assert result.passed is True
    assert result.debug is True


def test_tdx_parse_reads_td_attributes_from_the_signed_body():
    quote, _ = _build_quote(bytes.fromhex(DIGEST), td_attributes=TDX_TD_ATTR_DEBUG)
    parsed = parse_tdx_quote(quote)
    assert parsed.td_attributes == 1
    assert parsed.debug is True


_HARDWARE = os.path.join(os.path.dirname(__file__), "fixtures", "hardware", "gcp-tdx-2026-07-21")


@pytest.mark.parametrize("name", ["tdx_quote.bin", "tdx_quote_manifest.bin"])
def test_real_gcp_tdx_captures_are_not_debug(name):
    with open(os.path.join(_HARDWARE, name), "rb") as fh:
        parsed = parse_tdx_quote(fh.read())
    # Bit 28 (SEPT_VE_DISABLE) set and DEBUG clear, which is also what pins
    # the TDATTRIBUTES offset to a real quote rather than a synthetic one.
    assert parsed.td_attributes == 0x10000000
    assert parsed.debug is False


# --- runtime freshness: no opt-in ------------------------------------------

CONTEXT_HASH = "sha256:" + hashlib.sha256(b"live context").hexdigest()


def _qualifying(nonce: bytes) -> bytes:
    return hashlib.sha256(nonce + bytes.fromhex(CONTEXT_HASH[7:])).digest()


def _runtime_report(platform: str, nonce: bytes, quote) -> RuntimeAttestationReport:
    return RuntimeAttestationReport(
        platform=platform,
        report_data_hash="sha256:" + hashlib.sha256(_qualifying(nonce)).hexdigest(),
        context_hash=CONTEXT_HASH,
        nonce_hex=nonce.hex(),
        quote=quote,
        raw={},
    )


@pytest.mark.parametrize(
    "policy,vmpl,ok",
    [
        (_PRODUCTION_POLICY, 0, True),
        (_PRODUCTION_POLICY | SNP_POLICY_DEBUG, 0, False),
        (_PRODUCTION_POLICY, 1, False),
    ],
)
def test_runtime_quote_from_snp_guest_state(policy, vmpl, ok):
    nonce = os.urandom(32)
    snp, vcek_der, chain = build_synthetic_snp_report_with_chain(
        _qualifying(nonce).hex(), MEASUREMENT, policy=policy, vmpl=vmpl
    )
    reasons: list[str] = []
    got = verify_runtime_quote(
        _runtime_report("amd-sev-snp", nonce, snp),
        nonce,
        CONTEXT_HASH,
        vcek_cert_der=vcek_der,
        cert_chain_pem=chain,
        trusted_ark_der=ark_der_from_chain(chain),
        reasons=reasons,
    )
    assert got is ok, reasons


@pytest.mark.parametrize("td_attributes,ok", [(0, True), (TDX_TD_ATTR_DEBUG, False)])
def test_runtime_quote_from_tdx_guest_state(td_attributes, ok):
    nonce = os.urandom(32)
    quote, root_pem = _build_quote(_qualifying(nonce), td_attributes=td_attributes)
    reasons: list[str] = []
    got = verify_runtime_quote(
        _runtime_report("intel-tdx", nonce, quote),
        nonce,
        CONTEXT_HASH,
        trusted_tdx_root_pem=root_pem,
        reasons=reasons,
    )
    assert got is ok, reasons
