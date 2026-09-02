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
from typing import Optional


def ak_modulus_hex_from_runtime_data(runtime_data: bytes) -> Optional[str]:
    """Extract the ``HCLAkPub`` RSA modulus (hex) from Azure HCL runtime-data JSON.

    Returns ``None`` on any malformed input (bad JSON, missing key, bad
    base64) rather than raising -- callers treat that as "cannot establish
    the binding", i.e. fail closed.
    """
    try:
        keys = json.loads(runtime_data).get("keys", [])
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        return None
    ak = next((k for k in keys if isinstance(k, dict) and k.get("kid") == "HCLAkPub"), None)
    if ak is None or "n" not in ak:
        return None
    try:
        n_b64 = ak["n"] + "=" * ((4 - len(ak["n"]) % 4) % 4)
        return base64.urlsafe_b64decode(n_b64).hex()
    except (binascii.Error, ValueError, TypeError):
        return None


def verify_azure_manifest_binding(
    *,
    expected_manifest_hash: str,
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
         equals the PCR digest inside the AK-signed TPM quote;
      2. ``quote_sig`` is a valid AK signature over ``quote_msg`` under
         ``ak_pub_pem``;
      3. ``ak_pub_pem`` is the exact key the runtime data names as
         ``HCLAkPub``;
      4. the runtime data hashes into ``REPORT_DATA`` of the signed SNP
         report bytes on ``snp_report_bytes``.

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

    # 3. ak_pub_pem is the exact key runtime_data describes as HCLAkPub.
    if not isinstance(ak_key, rsa.RSAPublicKey):
        return False
    numbers = ak_key.public_numbers()
    ak_modulus_hex = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big").hex()
    runtime_ak_modulus_hex = ak_modulus_hex_from_runtime_data(runtime_data)
    if runtime_ak_modulus_hex is None:
        return False
    if not hmac.compare_digest(ak_modulus_hex.lower(), runtime_ak_modulus_hex.lower()):
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
