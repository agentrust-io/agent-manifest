"""Composite Azure vTPM/SNP manifest-binding verification.

On Azure confidential VMs the guest does not control SNP's ``REPORT_DATA``
(the Hyper-V paravisor binds the vTPM AK there instead), so the manifest hash
cannot be checked directly against ``REPORT_DATA`` the way it is on
bare-metal SEV-SNP. Azure's real binding is a four-link chain:

  1. The manifest PCR value is exactly one extension of the manifest hash,
     and that value is the PCR digest carried *inside* an AK-signed TPM quote
     (not a free-text ``pcr_read`` string -- that is unauthenticated).
  2. The quote signature verifies under the claimed AK public key.
  3. That AK public key is the exact key the runtime data names as
     ``HCLAkPub`` -- i.e. this AK, not some other key.
  4. The runtime data hashes into ``REPORT_DATA`` of the *signed* SNP report
     bytes -- i.e. this runtime data (and therefore this AK) is bound into
     this exact report. The report's own VCEK<-ASK<-ARK signature chain is a
     separate, mandatory check performed by the caller; together the two
     checks tie the AK all the way to silicon.

:func:`verify_azure_manifest_binding` is the single place this chain is
established. Nothing else -- not a platform label, not a caller-supplied
boolean, not a self-reported flag on the report -- may substitute for
actually running it. Both :class:`AzureCVMProvider.verify_manifest_in_report`
and :func:`agent_manifest._attestation.verify_attestation_chain` call this
same function so there is exactly one implementation of the security
property, not two that can drift apart.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from typing import Any, Optional


# RFC 7515 base64url: unpadded, alphabet A-Za-z0-9-_ only. Python's
# ``base64.urlsafe_b64decode`` (and ``b64decode`` without ``validate=True``)
# silently *discards* any character outside the standard base64 alphabet
# before decoding, rather than rejecting it -- so a JWK member like
# ``"!!!!<realvalue>"`` decodes to the same bytes as ``"<realvalue>"`` with
# no error. That lets attacker-corrupted-but-cryptographically-committed
# JWK material decode "successfully" to whatever bytes survive the silent
# filtering, defeating the "fail closed on malformed input" contract these
# helpers document. Reject anything outside the unpadded URL-safe alphabet
# up front, then decode strictly.
_B64URL_ALPHABET_RE = re.compile(r"[A-Za-z0-9_-]*")


def _strict_b64url_decode(value: str) -> bytes:
    """Decode a JWK base64url member, rejecting anything but the exact,
    unpadded, URL-safe alphabet.

    Raises ``binascii.Error`` (caught by callers, which fail closed) if
    ``value`` contains characters outside ``A-Za-z0-9-_`` -- including
    standard-base64 ``+``/``/`` (and their padding ``=``), any illegal
    prefix/suffix such as stray punctuation, and (via ``fullmatch``, not a
    ``$``-anchored pattern) a trailing newline, which Python's ``$`` would
    otherwise let slip through one character before the end of the string.
    This is stricter than ``base64.urlsafe_b64decode``, which silently
    drops out-of-alphabet characters -- including embedded/trailing
    newlines -- instead of raising.
    """
    if not isinstance(value, str) or not _B64URL_ALPHABET_RE.fullmatch(value):
        raise binascii.Error("invalid base64url alphabet")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded)


def _find_hcl_ak_jwk(runtime_data: bytes) -> Optional[dict[str, Any]]:
    """Return the ``HCLAkPub`` JWK dict from Azure HCL runtime-data JSON, or ``None``.

    Fails closed (returns ``None``, never raises) on any malformed input:
    bad JSON, non-UTF-8 bytes, a top-level value that isn't an object, a
    ``"keys"`` value that isn't a list (e.g. ``{"keys": 1}``, which would
    otherwise blow up trying to iterate an int), or list entries that aren't
    key-shaped objects.
    """
    try:
        parsed = json.loads(runtime_data)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    keys = parsed.get("keys", [])
    if not isinstance(keys, list):
        return None
    return next((k for k in keys if isinstance(k, dict) and k.get("kid") == "HCLAkPub"), None)


def ak_modulus_hex_from_runtime_data(runtime_data: bytes) -> Optional[str]:
    """Extract the ``HCLAkPub`` RSA modulus (hex) from Azure HCL runtime-data JSON.

    Returns ``None`` on any malformed input (bad JSON, missing key, bad
    base64) rather than raising -- callers treat that as "cannot establish
    the binding", i.e. fail closed.

    An RSA public key is the pair ``(n, e)``, not ``n`` alone: this helper is
    kept for callers (e.g. matching a vTPM persistent handle by modulus) that
    only need the modulus, but a security decision that means to authenticate
    the *exact* key must use :func:`ak_public_numbers_from_runtime_data`
    instead, which also checks the exponent.

    """
    ak = _find_hcl_ak_jwk(runtime_data)
    if ak is None or "n" not in ak:
        return None
    try:
        return _strict_b64url_decode(ak["n"]).hex()
    except (binascii.Error, ValueError, TypeError):
        return None


def ak_public_numbers_from_runtime_data(runtime_data: bytes) -> Optional[tuple[str, int]]:
    """Extract the ``HCLAkPub`` RSA public numbers ``(n, e)`` from runtime data.

    Returns ``(modulus_hex, exponent_int)``, or ``None`` on any malformed
    input (bad JSON, missing/malformed ``n`` or ``e``, bad base64) -- never
    raises. Both values must be checked to authenticate the exact key: a
    modulus match alone does not establish ``e`` also matches, and a
    different ``e`` describes a different key even with the same ``n``.
    """
    ak = _find_hcl_ak_jwk(runtime_data)
    if ak is None or "n" not in ak or "e" not in ak:
        return None
    try:
        n_hex = _strict_b64url_decode(ak["n"]).hex()
        e_int = int.from_bytes(_strict_b64url_decode(ak["e"]), "big")
    except (binascii.Error, ValueError, TypeError):
        return None
    return n_hex, e_int


def verify_azure_manifest_binding(
    *,
    expected_manifest_hash: str,
    expected_pcr_index: int,
    quote_msg_b64: Optional[str],
    quote_sig_b64: Optional[str],
    ak_pub_pem: Optional[str],
    runtime_data_hex: Optional[str],
    snp_report_bytes: Optional[bytes],
) -> bool:
    """Authenticate the composite Azure manifest-binding chain end to end.

    Verifies, purely from the evidence given -- never from a platform label,
    a caller-supplied boolean, or any self-reported flag:

      1. the manifest PCR value (one extension of ``expected_manifest_hash``)
         equals the PCR digest inside the AK-signed TPM quote, *and* that
         digest is carried under a selection of exactly one PCR bank
         (SHA-256) and exactly one PCR index -- ``expected_pcr_index`` -- not
         merely a digest value that happens to match while the quote was
         actually signed over a different bank or PCR;
      2. ``quote_sig`` is a valid AK signature over ``quote_msg`` under
         ``ak_pub_pem``;
      3. ``ak_pub_pem`` is the exact key the runtime data names as
         ``HCLAkPub`` -- both the modulus *and* the exponent, since an RSA
         public key is the pair ``(n, e)`` and a modulus-only match lets a
         different exponent describe a different key;
      4. the runtime data hashes into ``REPORT_DATA`` of the signed SNP
         report bytes on ``snp_report_bytes``.

    ``expected_pcr_index`` is required and must come from verifier
    configuration (e.g. the ``AzureCVMProvider`` the caller actually
    configured), never inferred from a self-reported field like
    ``report.raw["pcr_index"]`` -- that field is not signed by anything and
    an attacker who controls the report controls it too.

    Returns ``True`` only when all four hold. Any missing, malformed, or
    mismatched input returns ``False`` -- this function never raises.
    """
    if not (quote_msg_b64 and quote_sig_b64 and ak_pub_pem and runtime_data_hex and snp_report_bytes):
        return False

    # Imports are local to avoid a module-load-time cycle: _snp_verify and
    # _tpm_verify are heavier modules not needed unless Azure binding is
    # actually being checked.
    from ._snp_verify import SnpVerificationError, parse_snp_report, verify_runtime_data_binding
    from ._tpm_verify import (
        TPM_ALG_SHA256,
        TPM_GENERATED_VALUE,
        TPM_ST_ATTEST_QUOTE,
        TpmVerificationError,
        parse_tpm_quote,
        verify_ak_signature,
    )
    try:
        quote_msg = base64.b64decode(quote_msg_b64, validate=True)
        quote_sig = base64.b64decode(quote_sig_b64, validate=True)
        runtime_data = bytes.fromhex(runtime_data_hex)
    except (binascii.Error, ValueError):
        return False

    # 1a. Expected PCR value: one extension of the manifest hash into a PCR
    # that started at zero.
    digest = expected_manifest_hash.split(":", 1)[-1].lower()
    try:
        expected_pcr_value = hashlib.sha256(bytes(32) + bytes.fromhex(digest)).digest()
    except ValueError:
        return False
    # tpm2_quote's PCR digest, for a single sha256 bank with a single PCR
    # selected, is sha256 of that PCR's raw (post-extend) value.
    expected_quote_pcr_digest = hashlib.sha256(expected_pcr_value).digest()

    try:
        quote = parse_tpm_quote(quote_msg)
    except TpmVerificationError:
        return False
    if quote.magic != TPM_GENERATED_VALUE or quote.attest_type != TPM_ST_ATTEST_QUOTE:
        return False
    # The boot-time quote is produced with a fixed all-zero qualifying value;
    # a fresh-nonce runtime quote (attest_runtime_state) must not be
    # replayable here as boot proof.
    if not hmac.compare_digest(quote.qualifying_data, bytes(16)):
        return False
    # 1b. That PCR digest is the one actually inside the AK-signed quote.
    if not hmac.compare_digest(quote.pcr_digest, expected_quote_pcr_digest):
        return False

    # 1c. The digest must be a digest *of the expected bank and PCR index*,
    # not merely a byte string that matches while the signed selection names
    # a different bank or PCR -- pcr_digest alone doesn't say which PCR(s) it
    # was computed over. Require exactly one selection: exactly one bank
    # (SHA-256) with exactly one PCR selected, and that PCR must be the one
    # this verifier is configured to check.
    if len(quote.pcr_selections) != 1:
        return False
    selection = quote.pcr_selections[0]
    if selection.hash_alg != TPM_ALG_SHA256:
        return False
    if selection.indices() != frozenset({expected_pcr_index}):
        return False

    # 2. quote_sig is a valid AK signature over quote_msg under ak_pub_pem.
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        ak_key = load_pem_public_key(ak_pub_pem.encode())
    except Exception:
        return False
    try:
        if not verify_ak_signature(ak_key, quote.raw, quote_sig):
            return False
    except TpmVerificationError:
        return False

    # 3. ak_pub_pem is the exact key runtime_data describes as HCLAkPub --
    # both the modulus and the exponent. An RSA public key is the pair
    # (n, e); comparing n alone would let runtime_data claim a different
    # exponent (a different key) while still "matching" on modulus.
    if not isinstance(ak_key, rsa.RSAPublicKey):
        return False
    numbers = ak_key.public_numbers()
    ak_modulus_hex = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big").hex()
    runtime_ak_numbers = ak_public_numbers_from_runtime_data(runtime_data)
    if runtime_ak_numbers is None:
        return False
    runtime_ak_modulus_hex, runtime_ak_exponent = runtime_ak_numbers
    if not hmac.compare_digest(ak_modulus_hex.lower(), runtime_ak_modulus_hex.lower()):
        return False
    if numbers.e != runtime_ak_exponent:
        return False

    # 4. runtime_data is bound (via REPORT_DATA) into the signed SNP report
    # bytes actually supplied.
    try:
        parsed_snp = parse_snp_report(snp_report_bytes)
    except SnpVerificationError:
        return False
    if not verify_runtime_data_binding(parsed_snp, runtime_data):
        return False

    return True
