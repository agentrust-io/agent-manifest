"""TRACE envelope and evidence pack verification (spec 6.3.2 / 5.2.1).

A TRACE envelope is the per-tool-call evidence record cMCP emits. It carries
the agent's manifest id, the manifest verification result at the time of the
call, the policy/catalog hashes actually in force, and the Cedar decision --
signed by a TEE-sealed key. An evidence pack bundles the manifest, a
verification result, the session's TRACE envelopes, and the raw attestation
report under a single detached ``pack_signature``.

Before this module the SDK stored ``trace_id`` and ``evidence_pack`` but never
checked either signature, so any field in a TRACE could be edited after the
fact and still be accepted as evidence (issue #204).

Two pre-images, both RFC 8785 canonical JSON:

  * TRACE envelope -- every field except ``signature``. Spec 6.3.2 types
    ``signature`` as a bare string ("Ed25519 | ML-DSA-65 by TEE-sealed key"),
    so there is no algorithm or key id in the envelope itself; the caller
    supplies both. Hybrid is not expressible here and is rejected.
  * Evidence pack -- every field except ``pack_signature``, which is the
    detached signature object of spec 3.6 (algorithm and key_id inside), so
    hybrid works there. Spec 5.2.1 defines ``pack_hash`` as the SHA-256 of
    exactly these bytes; :func:`compute_pack_hash` returns it.

Fail-closed throughout: a missing key, an unknown algorithm, or a build
without the post-quantum extra yields ``UNVERIFIABLE``, never ``VERIFIED``.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from ._canonicalize import canonicalize


# Fields every TRACE envelope MUST carry (spec 6.3.2). An envelope missing any
# of them is malformed: we refuse to report a signature over a record whose
# shape we cannot vouch for, because the absent field may be the one a relying
# party is about to read.
TRACE_REQUIRED_FIELDS: tuple[str, ...] = (
    "trace_id",
    "agent_id",
    "agent_manifest_id",
    "manifest_verification_result",
    "tool_id",
    "policy_hash",
    "catalog_hash",
    "decision",
    "decision_reason",
    "payload_classification",
    "egress_destination",
    "hitl_required",
    "timestamp",
    "tee_measurement",
    "signature",
)

# Spec 6.3.2: manifest_verification_result "MUST use the same enum values as
# the result field in section 5.2 - no additional values". OverallResult in
# _verify.py additionally carries the SDK's fail-closed SIGNATURE_MISSING and
# UNVERIFIABLE statuses; those are verifier-side outcomes and are NOT legal in
# a producer-written TRACE envelope, so this tuple is deliberately the spec 5.2
# seven and not a reference to that enum.
TRACE_VERIFICATION_RESULTS: tuple[str, ...] = (
    "VALID",
    "MISMATCH",
    "EXPIRED",
    "REVOKED",
    "INCOMPLETE",
    "ATTESTATION_UNAVAILABLE",
    "INCOMPATIBLE_VERSION",
)

# Spec 6.3.2: a TRACE in either state "MUST NOT be accepted as evidence of a
# valid tool call for regulatory reporting purposes" -- independent of whether
# its signature verifies.
INADMISSIBLE_RESULTS: frozenset[str] = frozenset({"MISMATCH", "EXPIRED"})

# The four members spec 5.2.1 defines an evidence pack as carrying, with the
# type each must have. They are checked before the signature, because a
# signature proves who assembled a document and not that the document is the
# thing it claims to be: a pack carrying nothing but its own `pack_signature`
# verifies perfectly and evidences nothing. An empty `manifest` in particular
# would silently disable the manifest-id and policy binding further down.
EVIDENCE_PACK_REQUIRED_FIELDS: dict[str, type] = {
    "manifest": dict,
    "verification_result": dict,
    "trace_envelopes": list,
    "attestation_report": str,
}

# Spec 6.3.2 fixes these three as closed enumerations. `manifest_verification_result`
# is checked separately against TRACE_VERIFICATION_RESULTS, which section 6.3.2
# requires to be the section 5.2 `result` values with no additions.
TRACE_DECISIONS: frozenset[str] = frozenset({"allow", "deny", "require-approval"})
PAYLOAD_CLASSIFICATIONS: frozenset[str] = frozenset(
    {"public", "internal", "confidential", "restricted"}
)

# Section 5.2 `result` values, for the verification result carried in a pack.
VERIFICATION_RESULTS: frozenset[str] = frozenset(TRACE_VERIFICATION_RESULTS) | {
    "SIGNATURE_MISSING",
    "UNVERIFIABLE",
}

# Formats the specification fixes exactly. Deliberately partial: `tee_measurement`
# is "<platform-specific measurement>" and `egress_destination` is
# "<FQDN | IP | none>", so neither has a shape this can enforce without
# rejecting records the spec permits. `tool_id` is a reverse-domain identifier
# with no stated grammar, so it is checked for emptiness only.
_UUID_V7 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SPIFFE = re.compile(r"^spiffe://[a-z0-9._-]+(/[a-zA-Z0-9._-]+)*$")

# Presence is not enough for a TRACE envelope either. A field carrying the
# wrong type passes a `in envelope` check and then flows into a comparison
# that silently does nothing: `policy_hash: []` never equals the manifest's
# hash, so the section 6.3.2 conflict rule would never fire against it.
TRACE_FIELD_TYPES: dict[str, type] = {
    "trace_id": str,
    "agent_id": str,
    "agent_manifest_id": str,
    "manifest_verification_result": str,
    "tool_id": str,
    "policy_hash": str,
    "catalog_hash": str,
    "decision": str,
    "decision_reason": str,
    "payload_classification": str,
    "egress_destination": str,
    # hitl_required is deliberately absent: it has a dedicated check further
    # down that names SCHEMA F-11 and says why a string is dangerous rather
    # than merely wrong. A generic message here would replace a specific one.
    "timestamp": str,
    "tee_measurement": str,
    "signature": str,
}

# Spec 6.3.2 types the envelope signature as a bare string, which cannot carry
# the two components a hybrid signature needs.
TRACE_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset({"Ed25519", "ML-DSA-65"})


class TraceStatus(str, Enum):
    """Outcome of appraising a TRACE envelope or evidence pack."""

    VERIFIED = "VERIFIED"
    # Signature material was present and did not verify.
    FAILED = "FAILED"
    # Present but unappraisable: no trusted key, unknown algorithm, or a build
    # without the [pq] extra. MUST NOT be treated as VERIFIED.
    UNVERIFIABLE = "UNVERIFIABLE"
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    # Required fields absent or an illegal enum value: shape cannot be trusted.
    MALFORMED = "MALFORMED"


@dataclass
class TraceVerificationResult:
    """Appraisal of one TRACE envelope.

    ``admissible`` is the question a relying party actually asks: may this
    record be used as evidence of a valid tool call? That needs a verified
    signature *and* a ``manifest_verification_result`` outside
    :data:`INADMISSIBLE_RESULTS`. A perfectly-signed envelope reporting
    ``MISMATCH`` is authentic and inadmissible at the same time -- the
    signature proves the runtime honestly recorded that the policy hash did
    not match, which is exactly the case spec 6.3.2 excludes from reporting.
    """

    status: TraceStatus
    trace_id: Optional[str] = None
    signature_verified: bool = False
    admissible: bool = False
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class EvidencePackVerificationResult:
    """Appraisal of an evidence pack and, optionally, the TRACEs inside it."""

    status: TraceStatus
    signature_verified: bool = False
    pack_hash: Optional[str] = None
    pack_hash_matches: Optional[bool] = None
    envelopes: list[TraceVerificationResult] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Pre-images
# ---------------------------------------------------------------------------


def trace_signing_pre_image(envelope: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes a TRACE ``signature`` covers.

    Every field except ``signature`` itself. Both producers and verifiers MUST
    call this so the byte sequences are identical.
    """
    return canonicalize({k: v for k, v in envelope.items() if k != "signature"})


def evidence_pack_pre_image(pack: dict[str, Any]) -> bytes:
    """Return the RFC 8785 canonical bytes ``pack_signature`` covers.

    Every field except ``pack_signature``, which spec 5.2.1 appends to the
    document after hashing and signing.
    """
    return canonicalize({k: v for k, v in pack.items() if k != "pack_signature"})


def compute_pack_hash(pack: dict[str, Any]) -> str:
    """Return ``"sha256:<64-hex>"`` over the pack's canonical bytes (spec 5.2.1)."""
    return f"sha256:{hashlib.sha256(evidence_pack_pre_image(pack)).hexdigest()}"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _select_key(
    trusted_keys: Optional[dict[str, str]],
    key_id: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """Resolve (public_key_b64url, failure_reason) from the caller's key set.

    A TRACE envelope carries no key id, so the caller names the key. When
    exactly one key is trusted the choice is unambiguous and we take it;
    otherwise we refuse rather than trying each key in turn, which would let
    an envelope silently pick whichever identity happens to verify it.
    """
    if not trusted_keys:
        return None, "no_trusted_keys"
    if key_id is not None:
        pub = trusted_keys.get(key_id)
        if pub is None:
            return None, f"key_id_not_trusted:{key_id}"
        return pub, None
    if len(trusted_keys) == 1:
        return next(iter(trusted_keys.values())), None
    return None, "ambiguous_key_id"


def _verify_detached(
    pre_image: bytes,
    signature_block: dict[str, Any],
    trusted_keys: dict[str, str],
) -> tuple[TraceStatus, list[str]]:
    """Verify a spec 3.6 detached signature object over *pre_image*.

    Mirrors the algorithm dispatch the manifest path uses in ``_verify.py``.
    """
    from cryptography.exceptions import InvalidSignature

    from ._signing import (
        AlgorithmUnavailableError,
        Ed25519Verifier,
        HybridVerifier,
        MlDsa65Verifier,
        _b64url_decode,
    )
    from ._verify import _split_hybrid_public_key

    algorithm = signature_block.get("algorithm")
    key_id = signature_block.get("key_id")
    if not algorithm:
        return TraceStatus.MALFORMED, ["signature_block_missing_algorithm"]
    if not key_id:
        return TraceStatus.MALFORMED, ["signature_block_missing_key_id"]

    pub_b64 = trusted_keys.get(key_id)
    if pub_b64 is None:
        return TraceStatus.UNVERIFIABLE, [f"key_id_not_trusted:{key_id}"]

    try:
        pub_bytes = _b64url_decode(pub_b64)
        sig_value = signature_block.get("signature_value", "")
        if algorithm == "Ed25519":
            Ed25519Verifier(pub_bytes).verify_bytes(pre_image, sig_value)
        elif algorithm == "ML-DSA-65":
            MlDsa65Verifier(pub_bytes).verify_bytes(pre_image, sig_value)
        elif algorithm == "hybrid-Ed25519-ML-DSA-65":
            ed_bytes, pq_bytes = _split_hybrid_public_key(key_id, pub_bytes)
            HybridVerifier(ed_bytes, pq_bytes).verify_bytes(pre_image, signature_block)
        else:
            return TraceStatus.UNVERIFIABLE, [f"unknown_algorithm:{algorithm!r}"]
    except AlgorithmUnavailableError as exc:
        # Capability gap, not a bad signature -- see AlgorithmUnavailableError.
        return TraceStatus.UNVERIFIABLE, [f"algorithm_unavailable:{exc}"]
    except InvalidSignature:
        return TraceStatus.FAILED, ["signature_invalid"]
    except (KeyError, ValueError) as exc:
        return TraceStatus.FAILED, [f"signature_malformed:{type(exc).__name__}"]

    return TraceStatus.VERIFIED, []


# ---------------------------------------------------------------------------
# TRACE envelope
# ---------------------------------------------------------------------------


def verify_trace_envelope(
    envelope: dict[str, Any],
    *,
    trusted_keys: Optional[dict[str, str]] = None,
    key_id: Optional[str] = None,
    algorithm: str = "Ed25519",
    manifest: Optional[dict[str, Any]] = None,
) -> TraceVerificationResult:
    """Verify one TRACE envelope's signature and manifest binding (spec 6.3.2).

    Args:
        envelope: The TRACE envelope dict.
        trusted_keys: key_id (sha256 hex of raw public key bytes) -> base64url
            public key. The envelope carries no key id of its own.
        key_id: Which trusted key signed this envelope. Optional when exactly
            one key is trusted.
        algorithm: ``"Ed25519"`` or ``"ML-DSA-65"``. Spec 6.3.2 types the
            envelope signature as a bare string, so hybrid is not expressible.
        manifest: When supplied, enforces the spec 6.3.2 hash-conflict rule
            (SCHEMA F-21) against ``artifacts.policy_bundle.hash``.

    Returns:
        A :class:`TraceVerificationResult`. Check ``admissible`` before using
        the envelope as evidence -- a verified signature alone is not enough.
    """
    result = TraceVerificationResult(status=TraceStatus.MALFORMED)
    result.trace_id = envelope.get("trace_id") if isinstance(envelope, dict) else None

    if not isinstance(envelope, dict):
        result.failures.append("envelope_not_an_object")
        return result

    missing = [f for f in TRACE_REQUIRED_FIELDS if f not in envelope]
    if missing:
        result.failures.append("missing_required_fields:" + ",".join(missing))
        return result

    # Presence checked, now shape.
    wrong_type = [
        name
        for name, want in TRACE_FIELD_TYPES.items()
        if not isinstance(envelope[name], want)
    ]
    if wrong_type:
        result.failures.append("wrong_field_type:" + ",".join(sorted(wrong_type)))
        return result

    # Type checked, now value. A field of the right type carrying a value the
    # specification does not define is still a non-conforming record, and
    # calling one admissible would label it as evidence of a valid tool call.
    bad_format = _envelope_format_failures(envelope)
    if bad_format:
        result.failures.extend(bad_format)
        return result

    mvr = envelope["manifest_verification_result"]
    if mvr not in TRACE_VERIFICATION_RESULTS:
        result.failures.append(f"illegal_manifest_verification_result:{mvr!r}")
        return result

    if not isinstance(envelope["hitl_required"], bool):
        # SCHEMA F-11 fixed this to a JSON boolean; a string "true" would make
        # an unapproved call look approved to a reader doing a truthiness test.
        result.failures.append("hitl_required_not_a_boolean")
        return result

    signature = envelope["signature"]
    if not signature or not isinstance(signature, str):
        result.status = TraceStatus.SIGNATURE_MISSING
        result.failures.append("signature_absent_or_not_a_string")
        return result

    if algorithm not in TRACE_SIGNATURE_ALGORITHMS:
        result.status = TraceStatus.UNVERIFIABLE
        result.failures.append(f"unsupported_envelope_algorithm:{algorithm!r}")
        return result

    pub_b64, key_failure = _select_key(trusted_keys, key_id)
    if pub_b64 is None:
        result.status = TraceStatus.UNVERIFIABLE
        result.failures.append(key_failure or "no_trusted_keys")
        return result

    from cryptography.exceptions import InvalidSignature

    from ._signing import (
        AlgorithmUnavailableError,
        Ed25519Verifier,
        MlDsa65Verifier,
        _b64url_decode,
    )

    pre_image = trace_signing_pre_image(envelope)
    try:
        pub_bytes = _b64url_decode(pub_b64)
        if algorithm == "Ed25519":
            Ed25519Verifier(pub_bytes).verify_bytes(pre_image, signature)
        else:
            MlDsa65Verifier(pub_bytes).verify_bytes(pre_image, signature)
    except AlgorithmUnavailableError as exc:
        result.status = TraceStatus.UNVERIFIABLE
        result.failures.append(f"algorithm_unavailable:{exc}")
        return result
    except InvalidSignature:
        result.status = TraceStatus.FAILED
        result.failures.append("signature_invalid")
        return result
    except ValueError as exc:
        result.status = TraceStatus.FAILED
        result.failures.append(f"signature_malformed:{exc}")
        return result

    result.status = TraceStatus.VERIFIED
    result.signature_verified = True

    if manifest is not None:
        result.warnings.extend(_check_manifest_binding(envelope, manifest, result))

    # Spec 6.3.2: MISMATCH and EXPIRED are never admissible as evidence of a
    # valid tool call, however good the signature is.
    if mvr in INADMISSIBLE_RESULTS:
        result.failures.append(f"inadmissible_manifest_verification_result:{mvr}")
        result.admissible = False
    else:
        result.admissible = not result.failures

    return result


def _is_utc_iso8601(value: str) -> bool:
    """True when *value* is an ISO 8601 timestamp that states UTC.

    Spec 6.3.2 types ``timestamp`` as ISO 8601 UTC, so an offset-naive string
    is rejected rather than assumed: a record whose time zone has to be
    guessed cannot be relied on to order events in an audit trail.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return False
    offset = parsed.utcoffset()
    if offset is None:
        return False
    return offset.total_seconds() == 0


def _envelope_format_failures(envelope: dict[str, Any]) -> list[str]:
    """Value-level checks for the fields spec 6.3.2 defines exactly.

    Only the fields with a stated shape are checked. ``tee_measurement`` is
    "<platform-specific measurement>" and ``egress_destination`` is
    "<FQDN | IP | none>", so enforcing a pattern on either would reject
    records the specification permits.
    """
    failures: list[str] = []

    for field_name in ("trace_id", "agent_manifest_id"):
        if not _UUID_V7.match(envelope[field_name]):
            failures.append(f"not_a_uuid_v7:{field_name}")

    # hitl_approval_id is "<UUID v7> | null", so null is legal and a present
    # value must be well formed.
    approval_id = envelope.get("hitl_approval_id")
    if approval_id is not None and (
        not isinstance(approval_id, str) or not _UUID_V7.match(approval_id)
    ):
        failures.append("not_a_uuid_v7:hitl_approval_id")

    if not _SPIFFE.match(envelope["agent_id"]):
        failures.append("not_a_spiffe_uri:agent_id")

    for field_name in ("policy_hash", "catalog_hash"):
        if not _SHA256.match(envelope[field_name]):
            failures.append(f"not_a_sha256_hash:{field_name}")

    if envelope["decision"] not in TRACE_DECISIONS:
        failures.append(f"illegal_decision:{envelope['decision']!r}")

    if envelope["payload_classification"] not in PAYLOAD_CLASSIFICATIONS:
        failures.append(
            f"illegal_payload_classification:"
            f"{envelope['payload_classification']!r}"
        )

    if not _is_utc_iso8601(envelope["timestamp"]):
        failures.append("not_an_iso8601_utc_timestamp:timestamp")

    for field_name in ("tool_id", "tee_measurement", "egress_destination"):
        if not envelope[field_name].strip():
            failures.append(f"empty_required_field:{field_name}")

    return failures


def _evidence_pack_content_failures(pack: dict[str, Any]) -> list[str]:
    """Value-level checks for the pack members spec 5.2.1 defines.

    A well-typed but empty member is the case this exists for: an empty
    ``verification_result`` carries no verdict, and an empty
    ``attestation_report`` is not a report. Either would let a pack that
    evidences nothing be labelled VERIFIED.
    """
    from ._signing import _b64url_decode

    failures: list[str] = []

    verification_result = pack["verification_result"]
    if not verification_result:
        failures.append("verification_result_empty")
    else:
        declared = verification_result.get("result")
        if declared is None:
            failures.append("verification_result_missing_result")
        elif declared not in VERIFICATION_RESULTS:
            failures.append(f"illegal_verification_result:{declared!r}")

    report = pack["attestation_report"]
    if not report:
        failures.append("attestation_report_empty")
    else:
        # Spec 5.2.1 carries the raw platform report base64url-encoded, so a
        # value that cannot be decoded is not a report this pack can produce.
        try:
            _b64url_decode(report)
        except Exception:
            failures.append("attestation_report_not_base64url")

    return failures


def _check_manifest_binding(
    envelope: dict[str, Any],
    manifest: dict[str, Any],
    result: TraceVerificationResult,
) -> list[str]:
    """Enforce the spec 6.3.2 hash-conflict rule (SCHEMA F-21).

    The manifest is authoritative for approved artifact hashes; the TRACE
    reports what was actually in force. When they disagree the producer MUST
    have written ``manifest_verification_result: MISMATCH``. An envelope that
    reports a conflicting ``policy_hash`` while still claiming ``VALID`` is a
    spec violation, and a self-serving one -- so it is a failure, not a
    warning.
    """
    warnings: list[str] = []

    envelope_manifest_id = envelope.get("agent_manifest_id")
    manifest_id = manifest.get("manifest_id")
    if manifest_id is not None and envelope_manifest_id != manifest_id:
        result.failures.append(
            f"manifest_id_mismatch:envelope={envelope_manifest_id!r},"
            f"manifest={manifest_id!r}"
        )
        return warnings

    artifacts = manifest.get("artifacts") or {}
    policy_bundle = artifacts.get("policy_bundle") or {}
    expected_policy_hash = policy_bundle.get("hash")

    if expected_policy_hash is None:
        warnings.append("manifest_has_no_policy_bundle_hash")
        return warnings

    if envelope.get("policy_hash") != expected_policy_hash:
        if envelope["manifest_verification_result"] != "MISMATCH":
            result.failures.append(
                "policy_hash_conflict_not_declared:"
                f"envelope={envelope.get('policy_hash')!r},"
                f"manifest={expected_policy_hash!r},"
                f"declared={envelope['manifest_verification_result']!r}"
            )

    return warnings


# ---------------------------------------------------------------------------
# Evidence pack
# ---------------------------------------------------------------------------


def verify_evidence_pack(
    pack: dict[str, Any],
    *,
    trusted_keys: Optional[dict[str, str]] = None,
    expected_pack_hash: Optional[str] = None,
    trace_key_id: Optional[str] = None,
    trace_algorithm: str = "Ed25519",
    verify_envelopes: bool = True,
) -> EvidencePackVerificationResult:
    """Verify an evidence pack's ``pack_signature`` and its TRACE envelopes.

    Args:
        pack: The evidence pack document (spec 5.2.1).
        trusted_keys: key_id -> base64url public key, covering both the pack's
            TEE-sealed key and the envelope signing key.
        expected_pack_hash: When supplied (e.g. the ``pack_hash`` carried in a
            verification result's ``evidence_pack`` reference), it is compared
            against the recomputed hash.
        trace_key_id: Key id for the envelopes inside the pack.
        trace_algorithm: Envelope signature algorithm.
        verify_envelopes: Set False to appraise only the pack signature.

    Returns:
        An :class:`EvidencePackVerificationResult`. ``status`` is ``VERIFIED``
        only when the pack signature verifies, any supplied ``pack_hash``
        matches, and (when checked) every envelope is admissible.
    """
    result = EvidencePackVerificationResult(status=TraceStatus.MALFORMED)

    if not isinstance(pack, dict):
        result.failures.append("pack_not_an_object")
        return result

    # Structure before signature. A pack carrying only its own `pack_signature`
    # would otherwise verify: the pre-image is computed over whatever is
    # present, the signature covers it honestly, and the result says VERIFIED
    # about a document with no manifest, no verification result, no envelopes
    # and no attestation report in it.
    missing = [f for f in EVIDENCE_PACK_REQUIRED_FIELDS if f not in pack]
    if missing:
        result.failures.append("missing_required_fields:" + ",".join(missing))
        return result

    wrong_type = [
        name
        for name, want in EVIDENCE_PACK_REQUIRED_FIELDS.items()
        if not isinstance(pack[name], want)
    ]
    if wrong_type:
        result.failures.append("wrong_field_type:" + ",".join(sorted(wrong_type)))
        return result

    # An empty manifest is well-typed and still useless: every binding check
    # downstream reads from it, so an empty one disables them all silently.
    if not pack["manifest"]:
        result.failures.append("manifest_empty")
        return result

    # Non-empty is not enough either. `_check_manifest_binding` skips the
    # manifest-id comparison when the manifest carries no `manifest_id`, so a
    # manifest of `{"note": "..."}` is well-typed, non-empty, and still lets an
    # envelope naming a completely different manifest through unremarked. The
    # binding is the reason the manifest is in the pack at all, so the field it
    # binds on is required rather than optional.
    if not isinstance(pack["manifest"].get("manifest_id"), str) or not pack[
        "manifest"
    ]["manifest_id"]:
        result.failures.append("manifest_missing_manifest_id")
        return result

    # Members present and well typed, now their contents. Also before the
    # signature: an empty verification_result carries no verdict and an empty
    # attestation_report is not a report, so a pack containing either
    # evidences nothing however well it is signed.
    content_failures = _evidence_pack_content_failures(pack)
    if content_failures:
        result.failures.extend(content_failures)
        return result

    result.pack_hash = compute_pack_hash(pack)
    if expected_pack_hash is not None:
        # Constant-time compare is unnecessary: both values are public hashes
        # and an attacker who can supply one can compute the other.
        result.pack_hash_matches = result.pack_hash == expected_pack_hash
        if not result.pack_hash_matches:
            result.failures.append(
                f"pack_hash_mismatch:computed={result.pack_hash},"
                f"expected={expected_pack_hash}"
            )

    signature_block = pack.get("pack_signature")
    if not signature_block:
        result.status = TraceStatus.SIGNATURE_MISSING
        result.failures.append("pack_signature_absent")
        return result
    if not isinstance(signature_block, dict):
        # Spec 5.2.1 requires the detached object form of 3.6, not a bare string.
        result.failures.append("pack_signature_not_a_detached_object")
        return result

    status, failures = _verify_detached(
        evidence_pack_pre_image(pack), signature_block, trusted_keys or {}
    )
    result.status = status
    result.failures.extend(failures)
    result.signature_verified = status is TraceStatus.VERIFIED

    if verify_envelopes:
        envelopes = pack.get("trace_envelopes") or []
        if not isinstance(envelopes, list):
            result.failures.append("trace_envelopes_not_an_array")
            result.status = TraceStatus.MALFORMED
            return result
        manifest = pack.get("manifest") if isinstance(pack.get("manifest"), dict) else None
        for envelope in envelopes:
            result.envelopes.append(
                verify_trace_envelope(
                    envelope,
                    trusted_keys=trusted_keys,
                    key_id=trace_key_id,
                    algorithm=trace_algorithm,
                    manifest=manifest,
                )
            )
        if any(not e.admissible for e in result.envelopes):
            result.failures.append("pack_contains_inadmissible_envelope")

    # A pack is only VERIFIED when nothing at all went wrong; a good pack
    # signature over an inadmissible TRACE is still not usable evidence.
    if result.status is TraceStatus.VERIFIED and result.failures:
        result.status = TraceStatus.FAILED

    return result
