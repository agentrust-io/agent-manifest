"""TPM quote parsing and signature verification against a real Azure vTPM capture.

The vector below was produced on 2026-07-31 on a Standard_D2s_v5 Azure VM with
Trusted Launch, vTPM and secure boot enabled, Ubuntu 24.04, TPM manufacturer
MSFT. The AK was created with ``tpm2_createek`` followed by ``tpm2_createak``
(RSA, RSASSA, SHA-256) and the quote taken over PCRs 0-7 under a fresh 32-byte
nonce. It moved here from cmcp when the TPMT_SIGNATURE parse consolidated into
agent-manifest, so the code and the evidence that validates it stay together.

This vector is committed, unlike the SEV-SNP captures. It carries no per-CPU
hardware identifier: the AK public key belongs to a virtual TPM in a VM that no
longer exists, and the PCR values describe a stock Ubuntu image. Committing it
means the signature path is exercised on every PR rather than only when someone
sets a fixture directory.

Scope: this validates parsing and the AK signature. It establishes no key
provenance, because the AK certificate chain is a separate question that on
Azure is host-dependent (see LIMITATIONS.md).
"""
import base64

import pytest

crypto = pytest.importorskip("cryptography")

from agent_manifest._tpm_verify import (  # noqa: E402
    TPM_GENERATED_VALUE,
    TpmVerificationError,
    parse_tpm_quote,
    parse_tpmt_signature,
)

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

# Bare TPMS_ATTEST as written by `tpm2_quote -m`.
QUOTE_ATTEST = base64.b64decode(
    "/1RDR4AYACIAC1Gr2BpHLuEP6q3wUzFvxZPNyfm9bw98RBelxxduCCr7ACBJgPpvWQ1l+6Fc3u8LC7Au"
    "jPFVBEcFsa8HAb+gsuMjlgAAAAAAAeu7AAAAAwAAAAABICADEgASAAQAAAABAAsD/wAAACDUvEYCCXOU"
    "AOzy8r898/XnrH99z1VrFNtVJDUg6kRSag=="
)

# TPMT_SIGNATURE as written by `tpm2_quote -s`.
QUOTE_SIGNATURE = base64.b64decode(
    "ABQACwEASCi0Ht6m6zPVnt4HXAahI4V4DV9nHbjWCJT0kYZVtUUS7BLmv7pt/dY2tNjWTJXAZKXJCX5i"
    "43eo53eVzKjHN3AzFdvkLEK/ahjEQ2/D+Frb+sLe0FlfhvzgfgUyoQCDs9krmCnMy18fDjxOSO+Nm2uy"
    "Wyg38ZTUpR1fUmjb68n9WHbPR3QZV9nNI4G0IW3AgRhcHZ7gmb9WJdLLSRdzfFJ7wDWEsAFcrtGiycc0"
    "iRXbCOBh0xTeDTlIWn9ljEYTvDlr8duW3c2fT08ZcV4vxJA6Wa8cr1QQjpd6s1/UO0XaYXneCHxoGI1u"
    "fbEoR4QA3qTPYNCSKNgyHH9GdV1stg=="
)

AK_PUBLIC_PEM = base64.b64decode(
    "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFN"
    "SUlCQ2dLQ0FRRUF5K3pCVWdBQTcvZW5CMEdyWmQrdgo4OFgvd3F0U2VKZ2dCczBZU0lkcW5HLzF4SjNy"
    "MEpTc1hyZnJkSkpnU1BwL2t4bzY5eWVtMlhjUlBiVGIzbHQwCjJsakVyaTZlUjhjbEt5RmNFUFFMbUZC"
    "Qmg3RU5Lai9KV3FnWnJINHhLdW93Y1BlR0ltajJ2S1hlV21LclVmb1gKVU1wdmI3eTUyeTJpNU4vTERQ"
    "UUcrYnI5NFhyZlNQNFNKTmVJKzlWUUM1Q1ZzRDM1QmZEZncwOHNYNGd6dG5FSwp4SUpyZGFVRUgxRjFs"
    "MkxPUjJoT0FQcjI5MmxrYUlvdTVoNHF6Y3hwbm5NTTN1djF6Q2Y1ZU5rZ2QwZ1FLdUllCjZ2T2JMcStT"
    "ZURPWndmYzBTSzRIUjBRVEtNcnhEbSs5eEdnU3ZYeUlFVnVTOExwZzBsZGRYU1Uzd0xpUU5Td1EKOHdJ"
    "REFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
)

NONCE = bytes.fromhex("4980fa6f590d65fba15cdeef0b0bb02e8cf155044705b1af0701bfa0b2e32396")


def _ak() -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(AK_PUBLIC_PEM)
    assert isinstance(key, rsa.RSAPublicKey)
    return key


def _verifies(attest: bytes, sig_blob: bytes, key: rsa.RSAPublicKey) -> bool:
    """Rejected covers both outcomes a tampered input can produce: a blob that no
    longer parses, and one that parses but whose signature does not check out."""
    try:
        parsed = parse_tpmt_signature(sig_blob)
        signed = parse_tpm_quote(attest).raw
        key.verify(parsed.signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except Exception:
        return False
    return True


def test_parses_a_real_tpmt_signature() -> None:
    parsed = parse_tpmt_signature(QUOTE_SIGNATURE)

    assert parsed.sig_alg == 0x0014  # TPM_ALG_RSASSA
    assert parsed.hash_alg == 0x000B  # TPM_ALG_SHA256
    assert len(parsed.signature) == 256


def test_parses_a_real_bare_tpms_attest() -> None:
    quote = parse_tpm_quote(QUOTE_ATTEST)

    assert quote.magic == TPM_GENERATED_VALUE
    assert quote.qualifying_data == NONCE
    assert quote.raw == QUOTE_ATTEST


def test_the_same_quote_parses_under_tpm2b_framing() -> None:
    """A producer that writes TPM2B_ATTEST must appraise identically to one that
    writes a bare TPMS_ATTEST, and `raw` must stay the signed inner bytes."""
    wrapped = len(QUOTE_ATTEST).to_bytes(2, "big") + QUOTE_ATTEST

    quote = parse_tpm_quote(wrapped)

    assert quote.raw == QUOTE_ATTEST
    assert quote.qualifying_data == NONCE


def test_real_hardware_quote_signature_verifies() -> None:
    assert _verifies(QUOTE_ATTEST, QUOTE_SIGNATURE, _ak()) is True


def test_real_hardware_quote_verifies_under_tpm2b_framing() -> None:
    """The regression this guards: verifying over the outer TPM2B bytes rather
    than the inner TPMS_ATTEST rejects a genuine quote."""
    wrapped = len(QUOTE_ATTEST).to_bytes(2, "big") + QUOTE_ATTEST

    assert _verifies(wrapped, QUOTE_SIGNATURE, _ak()) is True


def test_the_quote_carries_the_nonce_it_was_taken_under() -> None:
    """extraData sits after the qualifiedSigner name; the signature is what makes
    it meaningful, since both fields are otherwise attacker-controllable."""
    assert parse_tpm_quote(QUOTE_ATTEST).qualifying_data == NONCE


@pytest.mark.parametrize("flip", [0, 40, -1])
def test_a_tampered_attest_is_rejected(flip: int) -> None:
    tampered = bytearray(QUOTE_ATTEST)
    tampered[flip] ^= 0x01

    assert _verifies(bytes(tampered), QUOTE_SIGNATURE, _ak()) is False


def test_a_tampered_signature_is_rejected() -> None:
    tampered = bytearray(QUOTE_SIGNATURE)
    tampered[-1] ^= 0x01

    assert _verifies(QUOTE_ATTEST, bytes(tampered), _ak()) is False


def test_a_different_key_does_not_verify() -> None:
    """A quote is only evidence if it verifies under the key the relying party
    expects."""
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()

    assert _verifies(QUOTE_ATTEST, QUOTE_SIGNATURE, other) is False


def test_unsupported_signature_algorithm_is_rejected() -> None:
    with pytest.raises(TpmVerificationError, match="unsupported signature algorithm"):
        parse_tpmt_signature(b"\x00\x99\x00\x0b\x00\x04abcd")


def test_truncated_signature_is_rejected() -> None:
    with pytest.raises(TpmVerificationError, match="truncated"):
        parse_tpmt_signature(QUOTE_SIGNATURE[:20])


def test_a_size_prefix_that_overruns_the_buffer_is_rejected() -> None:
    """The size comes from untrusted input, so a declared length longer than the
    blob must fail closed rather than parse whatever fits."""
    with pytest.raises(TpmVerificationError, match="no TPM_GENERATED magic"):
        parse_tpm_quote((len(QUOTE_ATTEST) + 64).to_bytes(2, "big") + QUOTE_ATTEST)


def test_a_corrupt_magic_is_not_reported_as_a_framing_fault() -> None:
    """A one-bit flip in the magic must be diagnosed as a bad magic, not silently
    reinterpreted as a TPM2B size prefix, or the error sends whoever is debugging
    it to the wrong problem."""
    corrupt = bytearray(QUOTE_ATTEST)
    corrupt[0] ^= 0x01

    with pytest.raises(TpmVerificationError, match="no TPM_GENERATED magic"):
        parse_tpm_quote(bytes(corrupt))
