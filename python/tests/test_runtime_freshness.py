"""verify_runtime_report reads the nonce binding from the verified quote.

GHSA-32q9-m5rc-rp3w. verify_runtime_report (and its alias
verify_runtime_freshness) compared ``report.report_data_hash`` with
``sha256(sha256(nonce || context_hash_bytes))``. That field is computed by the
provider and signed by nothing, and the quote was never opened, so an old
genuinely signed quote, or no quote at all, verified as fresh once the field
was recomputed for the new nonce. The check now verifies the quote and reads
the caller-controlled field (SNP REPORT_DATA, TDX REPORTDATA, TPM extraData)
out of the signed bytes.
"""

import base64
import hashlib
import json
import os

import pytest

pytest.importorskip("cryptography")

from agent_manifest import verify_runtime_report  # noqa: E402
from agent_manifest._attestation import verify_runtime_freshness  # noqa: E402
from agent_manifest._providers import RuntimeAttestationReport  # noqa: E402

from ._snp_synthetic import (  # noqa: E402
    ark_der_from_chain,
    build_synthetic_snp_report_with_chain,
)

CONTEXT_HASH = "sha256:" + hashlib.sha256(b"live context").hexdigest()
MEASUREMENT = "ab" * 48


def _qualifying(nonce: bytes) -> bytes:
    return hashlib.sha256(nonce + bytes.fromhex(CONTEXT_HASH[7:])).digest()


def _field(nonce: bytes) -> str:
    return "sha256:" + hashlib.sha256(_qualifying(nonce)).hexdigest()


def _report(platform: str, nonce: bytes, quote, raw=None) -> RuntimeAttestationReport:
    return RuntimeAttestationReport(
        platform=platform,
        report_data_hash=_field(nonce),
        context_hash=CONTEXT_HASH,
        nonce_hex=nonce.hex(),
        quote=quote,
        raw=raw or {},
    )


def _snp_quote_for(nonce: bytes):
    snp, vcek_der, chain = build_synthetic_snp_report_with_chain(
        _qualifying(nonce).hex(), MEASUREMENT
    )
    material = dict(
        vcek_cert_der=vcek_der, cert_chain_pem=chain, trusted_ark_der=ark_der_from_chain(chain)
    )
    return snp, material


# --- AMD SEV-SNP -----------------------------------------------------------


def test_snp_fresh_quote_verifies():
    nonce = os.urandom(32)
    snp, material = _snp_quote_for(nonce)
    assert verify_runtime_report(_report("amd-sev-snp", nonce, snp), nonce, CONTEXT_HASH, **material)
    assert verify_runtime_freshness(_report("amd-sev-snp", nonce, snp), nonce, CONTEXT_HASH, **material)


def test_snp_replayed_quote_with_recomputed_field_is_rejected():
    old_nonce, fresh_nonce = os.urandom(32), os.urandom(32)
    old_snp, material = _snp_quote_for(old_nonce)
    replay = _report("amd-sev-snp", fresh_nonce, old_snp)
    # Control: the unsigned field is exactly what an honest fresh report
    # carries, so only the signed quote can tell the two apart.
    assert replay.report_data_hash == _field(fresh_nonce)
    assert not verify_runtime_report(replay, fresh_nonce, CONTEXT_HASH)
    assert not verify_runtime_report(replay, fresh_nonce, CONTEXT_HASH, **material)
    assert not verify_runtime_freshness(replay, fresh_nonce, CONTEXT_HASH, **material)


def test_snp_report_without_a_quote_is_rejected():
    nonce = os.urandom(32)
    _, material = _snp_quote_for(nonce)
    assert not verify_runtime_report(_report("amd-sev-snp", nonce, None), nonce, CONTEXT_HASH)
    assert not verify_runtime_report(
        _report("amd-sev-snp", nonce, None), nonce, CONTEXT_HASH, **material
    )


def test_snp_quote_without_vcek_material_is_not_verified():
    nonce = os.urandom(32)
    snp, _ = _snp_quote_for(nonce)
    assert not verify_runtime_report(_report("amd-sev-snp", nonce, snp), nonce, CONTEXT_HASH)


def test_snp_quote_under_an_unpinned_root_is_not_verified():
    nonce = os.urandom(32)
    snp, material = _snp_quote_for(nonce)
    material.pop("trusted_ark_der")
    assert not verify_runtime_report(_report("amd-sev-snp", nonce, snp), nonce, CONTEXT_HASH, **material)


def test_snp_tampered_quote_is_rejected():
    nonce = os.urandom(32)
    snp, material = _snp_quote_for(nonce)
    tampered = bytearray(snp)
    tampered[0x90] ^= 0x01
    assert not verify_runtime_report(
        _report("amd-sev-snp", nonce, bytes(tampered)), nonce, CONTEXT_HASH, **material
    )


def test_wrong_nonce_is_rejected():
    nonce = os.urandom(32)
    snp, material = _snp_quote_for(nonce)
    assert not verify_runtime_report(
        _report("amd-sev-snp", nonce, snp), os.urandom(32), CONTEXT_HASH, **material
    )


# --- Intel TDX -------------------------------------------------------------


def _tdx_quote_for(nonce: bytes):
    import sys

    sys.path.insert(0, os.path.dirname(__file__))
    from test_tdx_verify import _build_quote

    return _build_quote(_qualifying(nonce))


def test_tdx_fresh_quote_verifies_and_replay_is_rejected():
    nonce, fresh = os.urandom(32), os.urandom(32)
    quote, root_pem = _tdx_quote_for(nonce)
    assert verify_runtime_report(
        _report("intel-tdx", nonce, quote), nonce, CONTEXT_HASH, trusted_tdx_root_pem=root_pem
    )
    replay = _report("intel-tdx", fresh, quote)
    assert replay.report_data_hash == _field(fresh)
    assert not verify_runtime_report(replay, fresh, CONTEXT_HASH, trusted_tdx_root_pem=root_pem)


# --- TPM -------------------------------------------------------------------


def _tpm_material(qualifying: bytes):
    import sys

    sys.path.insert(0, os.path.dirname(__file__))
    from test_tpm_verify import PCR, _ak_chain, _build_attest, _sign

    ak_key, chain, roots = _ak_chain()
    attest = _build_attest(qualifying, PCR)
    return dict(
        tpm_attest=attest,
        tpm_signature=_sign(ak_key, attest),
        tpm_ak_chain_pem=chain,
        tpm_trusted_roots_pem=roots,
    )


def test_tpm_fresh_quote_verifies_and_replay_is_rejected():
    nonce, fresh = os.urandom(32), os.urandom(32)
    material = _tpm_material(_qualifying(nonce))
    assert verify_runtime_report(_report("tpm", nonce, None), nonce, CONTEXT_HASH, **material)
    assert not verify_runtime_report(_report("tpm", fresh, None), fresh, CONTEXT_HASH, **material)
    assert not verify_runtime_report(_report("tpm", nonce, None), nonce, CONTEXT_HASH)


# --- Azure CVM (vTPM quote rooted in the SNP report) -----------------------


def _azure_runtime(nonce: bytes):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from .test_attestation_chain import _azure_build_attest, _azure_tpmt_sign

    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ak_pub_pem = ak_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()
    quote_msg = _azure_build_attest(_qualifying(nonce), b"\x22" * 32)
    quote_sig = _azure_tpmt_sign(ak_key, quote_msg)
    numbers = ak_key.public_key().public_numbers()
    n_b64 = base64.urlsafe_b64encode(
        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()
    runtime_data = json.dumps({"keys": [{"kid": "HCLAkPub", "n": n_b64, "e": "AQAB"}]}).encode()
    snp, vcek_der, chain = build_synthetic_snp_report_with_chain(
        hashlib.sha256(runtime_data).hexdigest(), MEASUREMENT
    )
    raw = {
        "ak_pub_pem": ak_pub_pem,
        "runtime_data_hex": runtime_data.hex(),
        "quote_msg": base64.b64encode(quote_msg).decode(),
        "quote_sig": base64.b64encode(quote_sig).decode(),
    }
    material = dict(
        vcek_cert_der=vcek_der, cert_chain_pem=chain, trusted_ark_der=ark_der_from_chain(chain)
    )
    return snp, raw, material


def test_azure_fresh_quote_verifies_and_replay_is_rejected():
    nonce, fresh = os.urandom(32), os.urandom(32)
    snp, raw, material = _azure_runtime(nonce)
    assert verify_runtime_report(
        _report("azure-cvm-sev-snp", nonce, snp, raw), nonce, CONTEXT_HASH, **material
    )
    assert not verify_runtime_report(
        _report("azure-cvm-sev-snp", fresh, snp, raw), fresh, CONTEXT_HASH, **material
    )
    # The AK must be the one the signed SNP report binds.
    _, other_raw, _ = _azure_runtime(nonce)
    swapped = dict(raw, quote_msg=other_raw["quote_msg"], quote_sig=other_raw["quote_sig"])
    assert not verify_runtime_report(
        _report("azure-cvm-sev-snp", nonce, snp, swapped), nonce, CONTEXT_HASH, **material
    )


# --- No hardware quote -----------------------------------------------------


@pytest.mark.parametrize("platform", ["software", "example-managed-runtime", ""])
def test_platforms_without_a_hardware_quote_do_not_verify(platform):
    nonce = os.urandom(32)
    report = _report(platform, nonce, None)
    assert report.report_data_hash == _field(nonce)
    assert not verify_runtime_report(report, nonce, CONTEXT_HASH)


@pytest.mark.parametrize("bad", ["sha256:" + "zz" * 32, "md5:" + "00" * 32, "", "sha256:"])
def test_malformed_context_hash_fails_closed(bad):
    nonce = os.urandom(32)
    assert not verify_runtime_report(_report("amd-sev-snp", nonce, None), nonce, bad)
