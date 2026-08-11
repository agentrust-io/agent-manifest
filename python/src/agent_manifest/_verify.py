"""Agent Manifest verification engine and FastAPI endpoint.

Two hosting modes (spec Section 5.1 / SPEC-07):
  SDK-hosted:    FastAPI server embedded in the agent process, served over
                 mTLS using the agent's SPIFFE SVID.  Runtime artifact hashes
                 are computed by the trusted component that holds the manifest.
  OPAQUE-hosted: Results are served from hashes pushed by the agent SDK at
                 startup to OPAQUE's attestation service.

The verification engine itself is hosting-agnostic - it takes a Manifest
dict and a set of running artifact hashes and produces a VerificationResult.
The FastAPI router wires the engine to HTTP.
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional, Union

from pydantic import BaseModel, Field

from ._cose import (
    COSE_MANIFEST_VERSION,
    MEDIA_TYPE_MANIFEST_COSE,
    CoseVerification,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class OverallResult(str, Enum):
    VALID = "VALID"
    MISMATCH = "MISMATCH"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    INCOMPLETE = "INCOMPLETE"
    ATTESTATION_UNAVAILABLE = "ATTESTATION_UNAVAILABLE"
    INCOMPATIBLE_VERSION = "INCOMPATIBLE_VERSION"
    # Fail-closed statuses (spec 5.3: VALID requires a valid signature):
    # SIGNATURE_MISSING - the manifest carries no signature block at all.
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    # UNVERIFIABLE - a signature or delegation chain is present but the
    # verifier lacks the key material to verify it. MUST NOT be treated
    # as VALID by relying parties.
    UNVERIFIABLE = "UNVERIFIABLE"


class FieldResult(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NOT_BOUND = "NOT_BOUND"
    EXPIRED = "EXPIRED"


class DelegationResult(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_PRESENT = "NOT_PRESENT"
    # Chain present but the verifier lacks the public keys (or constraint
    # evaluation capability) to verify it - spec 3.4.1 / 5.2.
    UNVERIFIABLE = "UNVERIFIABLE"


class HitlResult(str, Enum):
    APPROVED = "APPROVED"
    EXPIRED = "EXPIRED"
    NOT_REQUIRED = "NOT_REQUIRED"
    MISSING = "MISSING"
    APPROVAL_INSUFFICIENT = "APPROVAL_INSUFFICIENT"


class MismatchDetail(BaseModel):
    field: str
    expected_hash: str
    actual_hash: str
    delta_detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FieldsVerified(BaseModel):
    system_prompt: FieldResult = FieldResult.NOT_BOUND
    policy_bundle: FieldResult = FieldResult.NOT_BOUND
    tool_manifest: FieldResult = FieldResult.NOT_BOUND
    model_identity: FieldResult = FieldResult.NOT_BOUND
    rag_corpus: FieldResult = FieldResult.NOT_BOUND
    memory_baseline: FieldResult = FieldResult.NOT_BOUND
    decision_trace: FieldResult = FieldResult.NOT_BOUND
    supply_chain: FieldResult = FieldResult.NOT_BOUND
    delegation_chain: DelegationResult = DelegationResult.NOT_PRESENT
    hitl_record: HitlResult = HitlResult.NOT_REQUIRED


class EvidencePack(BaseModel):
    trace_id: Optional[str] = None
    signed_by: Optional[str] = None
    pack_hash: Optional[str] = None
    pack_uri: Optional[str] = None


class VerificationResult(BaseModel):
    verification_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    manifest_id: str
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    result: OverallResult
    signature_verified: bool = False
    attestation_verified: bool = False
    fields_verified: FieldsVerified = Field(default_factory=FieldsVerified)
    mismatch_details: list[MismatchDetail] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    evidence_pack: Optional[EvidencePack] = None
    verification_signature: Optional[str] = None


class ErrorResponse(BaseModel):
    """Error response schema (Schema F-13 fix - closes spec gap)."""

    error_code: str
    error_message: str
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    retry_after_seconds: Optional[int] = None


class RevocationRecord(BaseModel):
    manifest_id: str
    revoked_at: datetime
    reason: str
    revoked_by: str


class VerifyRequest(BaseModel):
    """Request body for ``POST /verify``.

    ``trusted_keys`` maps key_id (sha256 hex of the raw public key bytes) to
    the base64url-encoded public key. Signature verification is fail-closed:
    without trusted keys, a signed manifest yields ``UNVERIFIABLE`` and an
    unsigned manifest yields ``SIGNATURE_MISSING`` - never ``VALID``.

    ``trusted_key_issuers`` maps each trusted key_id to the issuer SPIFFE URIs
    authorized to sign manifests with that key. When supplied, key-to-issuer
    authorization is fail-closed.
    """

    manifest_id: str
    enforce_hitl: bool = False
    enforce_attestation: bool = False
    # key_id (sha256 hex of pub key bytes) -> base64url-encoded public key bytes
    trusted_keys: dict[str, str] = Field(default_factory=dict)
    # key_id -> issuer SPIFFE URIs authorized to use that signing key
    trusted_key_issuers: dict[str, list[str]] = Field(default_factory=dict)
    # principal_id -> base64url-encoded public key bytes (for delegation chain)
    delegation_public_keys: dict[str, str] = Field(default_factory=dict)
    # When True, a manifest without a delegation_chain is a verification failure
    require_delegation: bool = False


# ---------------------------------------------------------------------------
# Verification engine
# ---------------------------------------------------------------------------


class VerificationContext(BaseModel):
    """Runtime artifact hashes and keys provided by the trusted component."""

    system_prompt_hash: Optional[str] = None
    policy_bundle_hash: Optional[str] = None
    tool_catalog_hash: Optional[str] = None
    model_version: Optional[str] = None
    rag_corpus_merkle_root: Optional[str] = None
    memory_snapshot_hash: Optional[str] = None
    audit_chain_root: Optional[str] = None
    container_image_digest: Optional[str] = None
    enforce_hitl: bool = False
    enforce_attestation: bool = False
    min_slsa_level: int = 0
    # key_id (sha256 hex of pub key bytes) -> base64url-encoded public key bytes
    trusted_keys: dict[str, str] = Field(default_factory=dict)
    # key_id -> issuer SPIFFE URIs authorized to use that signing key
    trusted_key_issuers: dict[str, list[str]] = Field(default_factory=dict)
    # principal_id -> base64url-encoded public key bytes (for delegation chain)
    delegation_public_keys: dict[str, str] = Field(default_factory=dict)
    # When True, bound artifacts without runtime hashes cause INCOMPLETE result
    strict_artifact_verification: bool = False
    # When True, manifest must have a delegation chain
    require_delegation: bool = False
    # Conformance level for enforcing spec §3.2.5.1 poisoning_scan rules.
    # Level 0: not-scanned is permitted (warning only).
    # Level 1+: not-scanned is a verification failure.
    conformance_level: int = 0


# Manifest spec versions this verifier implementation can process (spec 2.4).
# The envelope follows the version, not a flag (ADR-0011): 0.1 is the detached
# canonical-JSON signature block, 0.2 is COSE. A 0.2 manifest presented as a
# bare dict has no signature at all - the COSE structure is the signature - so
# it is reported SIGNATURE_MISSING rather than reinterpreted.
SUPPORTED_MANIFEST_VERSIONS: frozenset[str] = frozenset({"0.1", "0.2"})
_HYBRID_ED25519_PUBLIC_KEY_BYTES = 32

# Signature algorithms that satisfy each declared crypto_profile (spec 4.1 /
# 4.2). The rule is deliberately one-directional: it rejects a signature that
# provides less than the declared profile requires, and permits one that
# provides more. A post-quantum profile carrying a classical-only signature is
# the downgrade spec 4.2 tells verifiers to reject; a standard profile carrying
# an ML-DSA-65 or hybrid signature is an issuer moving to dual-signing ahead of
# the profile flip, which is strictly stronger and not an attack.
KNOWN_SIGNATURE_ALGORITHMS: frozenset[str] = frozenset(
    {"Ed25519", "ML-DSA-65", "hybrid-Ed25519-ML-DSA-65"}
)
PROFILE_SIGNATURE_ALGORITHMS: dict[str, frozenset[str]] = {
    "standard": KNOWN_SIGNATURE_ALGORITHMS,
    "post-quantum": frozenset({"ML-DSA-65", "hybrid-Ed25519-ML-DSA-65"}),
}


def _split_hybrid_public_key(
    key_id: str,
    public_key_bytes: bytes,
) -> tuple[bytes, bytes]:
    """Split and authenticate a combined Ed25519 || ML-DSA-65 public key."""
    if len(public_key_bytes) <= _HYBRID_ED25519_PUBLIC_KEY_BYTES:
        raise ValueError(
            "Hybrid public key must be Ed25519 public key bytes followed by "
            "ML-DSA-65 public key bytes"
        )

    actual_key_id = hashlib.sha256(public_key_bytes).hexdigest()
    if not hmac.compare_digest(actual_key_id, key_id):
        raise ValueError(
            "Hybrid public key bytes do not match signature.key_id"
        )

    return (
        public_key_bytes[:_HYBRID_ED25519_PUBLIC_KEY_BYTES],
        public_key_bytes[_HYBRID_ED25519_PUBLIC_KEY_BYTES:],
    )


def _signature_key_issuer_mismatch(
    manifest: dict[str, Any],
    key_id: str,
    trusted_key_issuers: dict[str, list[str]],
) -> Optional[MismatchDetail]:
    """Return a mismatch when a trusted key is not authorized for the issuer."""
    if not trusted_key_issuers:
        return None

    issuer = manifest.get("issuer")
    if not isinstance(issuer, str) or not issuer:
        return MismatchDetail(
            field="signature.issuer",
            expected_hash="<manifest issuer authorized for signature key>",
            actual_hash="<missing manifest issuer>",
        )

    allowed_issuers = trusted_key_issuers.get(key_id)
    if not allowed_issuers:
        return MismatchDetail(
            field="signature.issuer",
            expected_hash=f"<key_id={key_id} authorized for issuer={issuer!r}>",
            actual_hash="<key_id has no issuer authorization>",
        )

    if issuer not in allowed_issuers:
        return MismatchDetail(
            field="signature.issuer",
            expected_hash=f"<issuer in trusted_key_issuers[{key_id!r}]>",
            actual_hash=f"<issuer={issuer!r}>",
        )

    return None


def _strict_schema_violations(manifest: dict[str, Any]) -> list[tuple[str, str]]:
    """Run the manifest through the Pydantic schema and return fail-closed errors.

    Returns a list of (location, message) tuples for every validation error
    that is NOT a tolerated "missing required field" error. An empty list
    means the manifest carries no disqualifying schema violation.

    Tolerated: ``missing`` errors only. Disqualifying: unknown fields
    (``extra_forbidden``), type errors, bad enums, unparseable or
    out-of-window timestamps, and any ``value_error`` raised by a model
    validator (e.g. the expiry-window rule).
    """
    from pydantic import ValidationError

    from .models import Manifest

    # An empty delegation_chain means "no delegation"; the engine already
    # normalizes it to absent (``manifest.get("delegation_chain") or []``).
    # The schema models it as ``min_length=1`` (omit when empty), so drop an
    # empty/None chain before validating to avoid flagging the benign idiom.
    if not manifest.get("delegation_chain"):
        manifest = {k: v for k, v in manifest.items() if k != "delegation_chain"}

    try:
        Manifest.model_validate(manifest)
    except ValidationError as exc:
        violations: list[tuple[str, str]] = []
        for err in exc.errors():
            if err.get("type") == "missing":
                continue
            loc = ".".join(str(p) for p in err.get("loc", ()))
            violations.append((loc, err.get("msg", "schema error")))
        return violations
    return []


def verify_manifest(
    manifest: Union[dict[str, Any], bytes],
    context: VerificationContext,
    revocation_store: "RevocationStore",
    *,
    _envelope: Optional[CoseVerification] = None,
) -> VerificationResult:
    """Core verification engine - hosting-model agnostic and fail-closed.

    Checks version compatibility, signature, expiry, revocation, artifact
    hashes, delegation chain, and HITL. Returns a VerificationResult with
    per-field status and mismatch details.

    Accepts either envelope, selected by what it is given (ADR-0011):

    - A ``dict`` is a version 0.1 manifest carrying a detached ``signature``
      block, verified over the RFC 8785 pre-image exactly as it always has been.
    - ``bytes`` are a version 0.2 COSE envelope (``COSE_Sign1`` or
      ``COSE_Sign``). The signature is checked over the payload as received,
      and receipts, attestation, and approvals are read from the unprotected
      header after the signature is settled.

    Fail-closed semantics (spec 5.3 - VALID requires a valid signature):

    - A manifest with an unsupported (or missing) ``version`` returns
      ``INCOMPATIBLE_VERSION`` without further processing (spec 2.4).
    - A manifest without a ``signature`` block returns ``SIGNATURE_MISSING``.
    - A signed manifest verified without any ``trusted_keys`` in the context
      returns ``UNVERIFIABLE`` - never ``VALID``.
    - A delegation chain that cannot be verified (no
      ``delegation_public_keys``) is marked ``UNVERIFIABLE`` and the overall
      result is ``UNVERIFIABLE`` (spec 3.4.1 / 5.2).
    - ``enforce_hitl=True`` with no ``hitl_record`` in the manifest is a
      failure (``HitlResult.MISSING`` and a non-VALID overall result).

    The ``_envelope`` parameter is internal: it carries an already-appraised
    COSE envelope into the shared pipeline and is not part of the public API.
    """
    from cryptography.exceptions import InvalidSignature

    if isinstance(manifest, (bytes, bytearray)):
        return _verify_cose_envelope(bytes(manifest), context, revocation_store)

    manifest_id = manifest.get("manifest_id", "unknown")
    result = VerificationResult(manifest_id=manifest_id, result=OverallResult.VALID)
    mismatches: list[MismatchDetail] = []
    fields = result.fields_verified

    # --- Schema validation (fail-closed). verify_manifest accepts a raw dict,
    # so it must run the manifest through the Pydantic guards before trusting
    # any field. This makes extra="forbid" (unknown fields), enum/type
    # constraints, the expiry window, and timestamp parsing actually apply on
    # the verify path. A malformed expires_at is a schema failure here, not a
    # silently non-expiring manifest.
    #
    # Only pure "missing required field" errors are tolerated: the engine
    # treats absent artifact bindings and metadata as NOT_BOUND and degrades
    # safely, and requiring every business field would reject otherwise
    # well-formed manifests the engine can still evaluate. Every other class of
    # error (unknown field, wrong type, bad enum, unparseable/out-of-window
    # timestamp, or any value_error from a model validator) fails closed.
    schema_violations = _strict_schema_violations(manifest)
    if schema_violations:
        result.result = OverallResult.MISMATCH
        for loc, msg in schema_violations:
            mismatches.append(MismatchDetail(
                field=f"schema:{loc}" if loc else "schema",
                expected_hash="<schema-valid manifest>",
                actual_hash=f"<{msg}>",
            ))
        result.mismatch_details = mismatches
        return result

    # --- Version negotiation (spec 2.2 / 2.4) - MUST be checked before
    # verifying so unsupported manifests are never silently misinterpreted.
    version = manifest.get("version")
    if version not in SUPPORTED_MANIFEST_VERSIONS:
        result.result = OverallResult.INCOMPATIBLE_VERSION
        return result

    # --- Revocation check (must happen before VALID can be returned)
    if revocation_store.is_revoked(manifest_id):
        result.result = OverallResult.REVOKED
        return result

    # --- Expiry check
    expires_at = manifest.get("expires_at")
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if exp < datetime.now(timezone.utc):
                result.result = OverallResult.EXPIRED
                return result
        except (ValueError, AttributeError):
            pass

    # --- Crypto profile downgrade check (spec 4.2: a verifier MUST reject
    # rather than silently fall back, "this prevents downgrade attacks during
    # the transition period").
    #
    # crypto_profile is inside the signing pre-image (SIGNED_FIELDS) but
    # signature.algorithm is not - the whole signature block is excluded from
    # the pre-image by section 3.6. An intermediary can therefore rewrite the
    # algorithm identifier without disturbing the signed bytes. Cross-checking
    # the unsigned identifier against the signed profile is what binds the two,
    # and it runs independently of trusted_keys: a post-quantum manifest
    # presented with a classical-only signature is a downgrade whether or not
    # this verifier holds the key to check that signature.
    #
    # None of this applies to a COSE envelope. There ``alg`` is in the
    # protected header, covered by the signature, so there is no unsigned
    # identifier to cross-check; the profile check ran during envelope
    # appraisal, and the signature was verified over the payload as received.
    # An empty sig_block skips both branches below.
    if _envelope is not None:
        sig_block: dict[str, Any] = {}
        signature_missing = False
        result.signature_verified = _envelope.verified
        # The key-to-issuer authorization is NOT part of envelope appraisal -
        # it is this engine's policy check, and skipping it on the COSE path
        # would let any trusted key sign for any issuer, which the v0.1 path
        # rejects. Every signer must be authorized, so a hybrid manifest
        # cannot smuggle an unauthorized component key alongside a valid one.
        for _signature in _envelope.signatures:
            _issuer_mismatch = _signature_key_issuer_mismatch(
                manifest, _signature.key_id, context.trusted_key_issuers
            )
            if _issuer_mismatch is not None:
                mismatches.append(_issuer_mismatch)
    else:
        sig_block = manifest.get("signature") or {}
        signature_missing = not sig_block
        if sig_block and manifest.get("version") == COSE_MANIFEST_VERSION:
            # The envelope follows the version (ADR-0011), and for 0.2 that is
            # COSE. `signature` is not a v0.2 field at all - the COSE structure
            # is the signature - so a 0.2 manifest carrying a detached block is
            # claiming the new version while using the old envelope, with the
            # unauthenticated algorithm identifier and the canonicalize-before-
            # verify step that ADR-0011 moved away from. Verifying it under v0.1
            # rules would make the version gate advisory and leave the phase 5
            # deprecation unenforceable, so it is rejected rather than accepted.
            mismatches.append(MismatchDetail(
                field="signature",
                expected_hash=(
                    f"<COSE envelope for manifest version "
                    f"{COSE_MANIFEST_VERSION}>"
                ),
                actual_hash="<v0.1 detached signature block>",
            ))
            sig_block = {}
            signature_missing = False
    profile_downgrade = False
    if sig_block:
        declared_profile = manifest.get("crypto_profile", "standard")
        permitted = PROFILE_SIGNATURE_ALGORITHMS.get(declared_profile)
        declared_algorithm = sig_block.get("algorithm")
        if declared_algorithm is None:
            # spec 3.6: algorithm is REQUIRED and unauthenticated, so an absent
            # identifier must not fall back to the classical default.
            profile_downgrade = True
            mismatches.append(MismatchDetail(
                field="signature.algorithm",
                expected_hash="<algorithm declared>",
                actual_hash="<algorithm absent>",
            ))
        # An unrecognised algorithm identifier is left to the signature
        # verification branch below, which reports it as such.
        elif (
            permitted is not None
            and declared_algorithm in KNOWN_SIGNATURE_ALGORITHMS
            and declared_algorithm not in permitted
        ):
            profile_downgrade = True
            mismatches.append(MismatchDetail(
                field="signature.algorithm",
                expected_hash=(
                    f"<crypto_profile={declared_profile} permits "
                    f"{'|'.join(sorted(permitted))}>"
                ),
                actual_hash=f"<algorithm={declared_algorithm}>",
            ))

    # --- Signature verification (CRYPTO-004, fail-closed per spec 5.3)
    if sig_block and context.trusted_keys and not profile_downgrade:
        algorithm = sig_block.get("algorithm", "Ed25519")
        key_id = sig_block.get("key_id", "")
        pub_b64 = context.trusted_keys.get(key_id)
        if pub_b64 is None:
            mismatches.append(MismatchDetail(
                field="signature",
                expected_hash=f"<key_id={key_id} in trusted_keys>",
                actual_hash="<key_id not found in trusted_keys>",
            ))
        else:
            issuer_mismatch = _signature_key_issuer_mismatch(
                manifest,
                key_id,
                context.trusted_key_issuers,
            )
            if issuer_mismatch is not None:
                mismatches.append(issuer_mismatch)
            else:
                from ._signing import (
                    AlgorithmUnavailableError,
                    Ed25519Verifier,
                    MlDsa65Verifier,
                    HybridVerifier,
                    _b64url_decode,
                )
                try:
                    pub_bytes = _b64url_decode(pub_b64)
                    if algorithm == "Ed25519":
                        Ed25519Verifier(pub_bytes).verify(manifest, sig_block.get("signature_value", ""))
                        result.signature_verified = True
                    elif algorithm == "ML-DSA-65":
                        MlDsa65Verifier(pub_bytes).verify(manifest, sig_block.get("signature_value", ""))
                        result.signature_verified = True
                    elif algorithm == "hybrid-Ed25519-ML-DSA-65":
                        # Hybrid key_id covers the registered combined public key:
                        # sha256(Ed25519 public bytes || ML-DSA-65 public bytes).
                        # Component key ids from the unsigned signature block are
                        # intentionally ignored.
                        ed_bytes, pq_bytes = _split_hybrid_public_key(key_id, pub_bytes)
                        HybridVerifier(ed_bytes, pq_bytes).verify(manifest, sig_block)
                        result.signature_verified = True
                    else:
                        mismatches.append(MismatchDetail(
                            field="signature",
                            expected_hash="<known algorithm: Ed25519|ML-DSA-65|hybrid-Ed25519-ML-DSA-65>",
                            actual_hash=f"<unknown algorithm: {algorithm!r}>",
                        ))
                except AlgorithmUnavailableError as e:
                    # The post-quantum profile needs the optional [pq] extra.
                    # Without it this build cannot appraise an ML-DSA-65 or
                    # hybrid signature at all. That is a capability gap, not a
                    # bad manifest, so it must not be reported as MISMATCH -
                    # and it must not escape as an exception either, since a
                    # manifest is untrusted input and verify_manifest() is
                    # expected to return a verdict. signature_verified stays
                    # False, so the fail-closed chain below yields UNVERIFIABLE
                    # (spec 4.2: a verifier that does not support the profile
                    # rejects rather than silently falling back).
                    result.warnings.append(
                        f"signature algorithm {algorithm} is not supported by this "
                        f"build, so the signature could not be appraised: {e}"
                    )
                except InvalidSignature:
                    mismatches.append(MismatchDetail(
                        field="signature",
                        expected_hash="<valid signature>",
                        actual_hash="<invalid signature>",
                    ))
                except ValueError as e:
                    mismatches.append(MismatchDetail(
                        field="signature",
                        expected_hash="<valid signature>",
                        actual_hash=f"<malformed: {e}>",
                    ))

    # --- Artifact hash verification
    artifacts = manifest.get("artifacts") or {}
    unverified_bound: list[str] = []  # bound artifacts with no runtime hash (VERIFY-001)

    def _check(field_name: str, manifest_val: Optional[str], runtime_val: Optional[str]) -> FieldResult:
        if manifest_val is None:
            return FieldResult.NOT_BOUND
        if runtime_val is None:
            unverified_bound.append(field_name)
            return FieldResult.NOT_BOUND
        # Constant-time comparison to prevent timing side-channels (CRYPTO-002)
        if hmac.compare_digest(manifest_val, runtime_val):
            return FieldResult.MATCH
        mismatches.append(MismatchDetail(
            field=field_name,
            expected_hash=manifest_val,
            actual_hash=runtime_val,
        ))
        return FieldResult.MISMATCH

    sp = artifacts.get("system_prompt") or {}
    fields.system_prompt = _check(
        "system_prompt",
        sp.get("hash"),
        context.system_prompt_hash,
    )

    pb = artifacts.get("policy_bundle") or {}
    fields.policy_bundle = _check(
        "policy_bundle",
        pb.get("hash"),
        context.policy_bundle_hash,
    )

    tm = artifacts.get("tool_manifest") or {}
    fields.tool_manifest = _check(
        "tool_manifest",
        tm.get("catalog_hash"),
        context.tool_catalog_hash,
    )

    mi = artifacts.get("model_identity") or {}
    # For api-deployed models, bind by version string, not binary hash
    mi_bound = mi.get("model_hash") or mi.get("version")
    fields.model_identity = _check(
        "model_identity",
        mi_bound,
        context.model_version,
    )

    rc = artifacts.get("rag_corpus") or {}
    fields.rag_corpus = _check(
        "rag_corpus",
        rc.get("merkle_root"),
        context.rag_corpus_merkle_root,
    )

    # --- Poisoning scan rules (spec §3.2.5.1)
    poisoning_scan = rc.get("poisoning_scan") or {}
    poisoning_result = poisoning_scan.get("result")
    if poisoning_result == "flagged":
        mismatches.append(MismatchDetail(
            field="rag_corpus.poisoning_scan",
            expected_hash="<result: clean or not-scanned>",
            actual_hash="<result: flagged>",
        ))
    elif poisoning_result == "not-scanned":
        if context.conformance_level >= 1:
            mismatches.append(MismatchDetail(
                field="rag_corpus.poisoning_scan",
                expected_hash="<result: clean>",
                actual_hash="<result: not-scanned>",
            ))
        else:
            result.warnings.append(
                "rag_corpus.poisoning_scan.result is 'not-scanned'; scan before Level 1 conformance"
            )

    mb = artifacts.get("memory_baseline") or {}
    if mb:
        from datetime import timedelta
        # Check TTL expiry for memory baseline
        ttl = mb.get("ttl_seconds")
        approved_at = mb.get("approved_at")
        baseline_expired = False
        if ttl and approved_at:
            try:
                approved = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
                if datetime.now(timezone.utc) > approved + timedelta(seconds=ttl):
                    baseline_expired = True
            except (ValueError, AttributeError):
                pass
        if baseline_expired:
            fields.memory_baseline = FieldResult.EXPIRED
        else:
            fields.memory_baseline = _check(
                "memory_baseline",
                mb.get("snapshot_hash"),
                context.memory_snapshot_hash,
            )

    dt = artifacts.get("decision_trace") or {}
    fields.decision_trace = _check(
        "decision_trace",
        dt.get("audit_chain_root"),
        context.audit_chain_root,
    )

    sc = artifacts.get("supply_chain") or {}
    fields.supply_chain = _check(
        "supply_chain",
        sc.get("container_image_digest"),
        context.container_image_digest,
    )

    # --- Delegation chain (VERIFY-002)
    chain = manifest.get("delegation_chain") or []
    if chain:
        if context.delegation_public_keys:
            try:
                from ._delegation import verify_delegation_chain
                from ._signing import _b64url_decode
                pub_keys = {
                    pid: _b64url_decode(b64)
                    for pid, b64 in context.delegation_public_keys.items()
                }
                # Bind the chain root to the manifest signing identity so a
                # valid chain cannot be grafted onto an unrelated manifest.
                manifest_issuer = manifest.get("issuer") or manifest.get("agent_id")
                verify_delegation_chain(
                    chain, pub_keys, manifest_id, manifest_issuer=manifest_issuer
                )
                fields.delegation_chain = DelegationResult.VALID
            except (InvalidSignature, ValueError) as e:
                fields.delegation_chain = DelegationResult.INVALID
                mismatches.append(MismatchDetail(
                    field="delegation_chain",
                    expected_hash="<valid chain>",
                    actual_hash=f"<invalid: {e}>",
                ))
        else:
            # No public keys provided - the chain cannot be verified.
            # Fail closed: surface UNVERIFIABLE rather than VALID (spec 3.4.1 / 5.2).
            fields.delegation_chain = DelegationResult.UNVERIFIABLE
    else:
        fields.delegation_chain = DelegationResult.NOT_PRESENT
        if context.require_delegation:
            mismatches.append(MismatchDetail(
                field="delegation_chain",
                expected_hash="<delegation chain present>",
                actual_hash="<delegation chain absent>",
            ))

    # --- HITL
    hitl = manifest.get("hitl_record")
    if hitl and isinstance(hitl, dict):
        required = hitl.get("required", False)
        approvals = hitl.get("approvals") or []
        if not required and not context.enforce_hitl:
            fields.hitl_record = HitlResult.NOT_REQUIRED
        elif not approvals:
            if context.enforce_hitl:
                mismatches.append(MismatchDetail(
                    field="hitl_record",
                    expected_hash="<approval present>",
                    actual_hash="<none>",
                ))
            fields.hitl_record = HitlResult.MISSING
        else:
            # Check if any approval has expired (HITL-001: parse failure must set all_ok=False)
            now = datetime.now(timezone.utc)
            all_ok = True
            for approval in approvals:
                approved_at = approval.get("approved_at", "")
                duration = approval.get("approved_scope", {}).get("approval_duration_seconds", 0)
                try:
                    ap_time = datetime.fromisoformat(approved_at.replace("Z", "+00:00"))
                    from datetime import timedelta
                    if now > ap_time + timedelta(seconds=duration):
                        all_ok = False
                        break
                except (ValueError, AttributeError):
                    # Unparseable timestamp - treat as expired to fail safe (HITL-001)
                    all_ok = False
                    break
            if not all_ok:
                # Expired approvals always add to mismatches regardless of enforce_hitl (HITL-002)
                mismatches.append(MismatchDetail(
                    field="hitl_record",
                    expected_hash="<valid unexpired approval>",
                    actual_hash="<approval expired or unparseable>",
                ))
            fields.hitl_record = HitlResult.APPROVED if all_ok else HitlResult.EXPIRED
    elif context.enforce_hitl:
        # enforce_hitl with no hitl_record at all - fail closed. Omitting the
        # record entirely MUST NOT be weaker than declaring it with no approvals.
        fields.hitl_record = HitlResult.MISSING
        mismatches.append(MismatchDetail(
            field="hitl_record",
            expected_hash="<hitl_record with valid approval>",
            actual_hash="<hitl_record absent>",
        ))

    # --- Attestation block verification (HW-010)
    # Check that manifest_hash_in_report matches the computed manifest hash.
    # In a COSE envelope the report is in the unprotected header, and what it
    # binds is sha256 of the payload bytes (envelope spec 5) - there is no
    # field subset to reconstruct and nothing to keep in sync.
    if _envelope is not None:
        attestation_block = _envelope.attestation or {}
    else:
        attestation_block = manifest.get("attestation") or {}
    if attestation_block:
        reported_hash = attestation_block.get("manifest_hash_in_report", "")
        if reported_hash:
            from ._canonicalize import canonicalize as _canonicalize
            import hashlib as _hashlib
            if _envelope is not None:
                expected_attest_hash = _envelope.manifest_hash
            else:
                # Spec 3.3: the pre-image excludes the attestation block AND the
                # top-level transparency_log_entry (populated after log submission).
                subset = {
                    k: v
                    for k, v in manifest.items()
                    if k not in ("attestation", "transparency_log_entry")
                }
                expected_attest_hash = "sha256:" + _hashlib.sha256(_canonicalize(subset)).hexdigest()
            if hmac.compare_digest(reported_hash, expected_attest_hash):
                result.attestation_verified = True
            elif context.enforce_attestation:
                mismatches.append(MismatchDetail(
                    field="attestation",
                    expected_hash=expected_attest_hash,
                    actual_hash=reported_hash,
                ))

    # --- Final result (fail-closed: VALID requires a verified signature and
    # a verifiable delegation chain - spec 5.3)
    result.mismatch_details = mismatches
    if mismatches:
        result.result = OverallResult.MISMATCH
    elif signature_missing:
        result.result = OverallResult.SIGNATURE_MISSING
    elif not result.signature_verified:
        # Signature present but no trusted keys (or verification never ran) -
        # the manifest cannot be authenticated. Never VALID.
        result.result = OverallResult.UNVERIFIABLE
    elif fields.delegation_chain == DelegationResult.UNVERIFIABLE:
        result.result = OverallResult.UNVERIFIABLE
    elif OverallResult.VALID == result.result:
        # VERIFY-001: bound artifacts with no runtime hashes in strict mode
        if context.strict_artifact_verification and unverified_bound:
            result.result = OverallResult.INCOMPLETE
        elif context.enforce_attestation and not result.attestation_verified:
            result.result = OverallResult.ATTESTATION_UNAVAILABLE

    # Surface bound-but-unchecked artifacts even in non-strict mode so callers
    # never read a VALID result as proof that artifact bindings were checked.
    # A signature-only VALID means the manifest is authentic, not that the
    # running artifacts match what it bound (VERIFY-001).
    if unverified_bound:
        result.warnings.append(
            "artifact bindings NOT verified (no runtime hashes provided for "
            + ", ".join(sorted(unverified_bound))
            + "); VALID reflects signature only"
        )

    return result


def _cose_manifest_id(cose_bytes: bytes) -> str:
    """Best-effort manifest_id for reporting a failed envelope.

    Reads the payload without appraising anything. Used only to label a
    result that has already been decided against the manifest.
    """
    from ._cose import read_payload_manifest

    try:
        manifest_id = read_payload_manifest(cose_bytes).get("manifest_id")
    except Exception:
        return "unknown"
    return manifest_id if isinstance(manifest_id, str) else "unknown"


def _verify_cose_envelope(
    cose_bytes: bytes,
    context: VerificationContext,
    revocation_store: "RevocationStore",
) -> VerificationResult:
    """Appraise a version 0.2 COSE envelope, then run the shared pipeline.

    The envelope is settled first and in full (envelope spec section 6): the
    structure, the protected header, the version, the profile, and the
    signature. Only then is the unprotected header read, and what it carries
    is evaluated by the same engine that evaluates a v0.1 manifest - approvals
    against the signed HITL requirement, the attestation report against the
    payload hash - so a v0.2 manifest gets the identical set of checks.
    """
    from cryptography.exceptions import InvalidSignature

    from ._cose import (
        CoseDowngradeError,
        CoseKeyError,
        CoseStructureError,
        CoseVersionError,
        verify_cose_manifest,
    )
    from ._signing import AlgorithmUnavailableError

    try:
        envelope = verify_cose_manifest(cose_bytes, context.trusted_keys)
    except CoseVersionError:
        # spec 2.4: an unsupported version is never silently misinterpreted.
        return VerificationResult(
            manifest_id=_cose_manifest_id(cose_bytes),
            result=OverallResult.INCOMPATIBLE_VERSION,
        )
    except AlgorithmUnavailableError as exc:
        # A capability gap, not a bad manifest, and never a fallback to a
        # weaker signature entry (envelope spec 2.1 and 6 step 6).
        return VerificationResult(
            manifest_id=_cose_manifest_id(cose_bytes),
            result=OverallResult.UNVERIFIABLE,
            warnings=[
                f"the COSE signature could not be appraised by this build: {exc}"
            ],
        )
    except (
        CoseStructureError,
        CoseKeyError,
        CoseDowngradeError,
        InvalidSignature,
        ValueError,
    ) as exc:
        return VerificationResult(
            manifest_id=_cose_manifest_id(cose_bytes),
            result=OverallResult.MISMATCH,
            mismatch_details=[
                MismatchDetail(
                    field="signature",
                    expected_hash="<valid COSE manifest envelope>",
                    actual_hash=f"<{exc}>",
                )
            ],
        )

    # Step 7. Approvals attach after signing, so they are merged back onto the
    # signed HITL requirement for evaluation. The requirement itself came out
    # of the payload and is covered by the signature; the approvals are not,
    # and each carries its own approval_signature (v0.1 section 3.5).
    payload_manifest = dict(envelope.manifest)
    approvals = envelope.approvals
    if approvals is not None:
        hitl_record = payload_manifest.get("hitl_record")
        if isinstance(hitl_record, dict):
            payload_manifest["hitl_record"] = {**hitl_record, "approvals": approvals}

    result = verify_manifest(
        payload_manifest, context, revocation_store, _envelope=envelope
    )

    if not envelope.receipts:
        result.warnings.append(
            "no transparency receipt in the unprotected header (label 394); "
            "a production manifest is expected to carry one"
        )
    return result


# ---------------------------------------------------------------------------
# Runtime attestation verification
# ---------------------------------------------------------------------------


def verify_runtime_report(
    report: Any,
    nonce: bytes,
    context_hash: str,
) -> bool:
    """Check the software-verifiable consistency of a RuntimeAttestationReport.

    Verifies that ``report.report_data_hash`` equals the expected derivation:
        sha256(sha256(nonce || bytes.fromhex(context_hash_hex)))

    This proves the report was produced for *this* nonce and *this* context_hash
    — i.e., it is not a replay of an older report. It does NOT verify the
    hardware signature on the underlying TEE quote blob; for that, use the
    platform vendor SDK (amd sev-snp-verify, Intel TDX Attest SDK,
    tpm2_checkquote) against ``report.quote``.

    Args:
        report:       RuntimeAttestationReport returned by attest_runtime_state().
        nonce:        The freshness token you supplied to attest_runtime_state().
        context_hash: The context hash you supplied to attest_runtime_state(),
                      in "sha256:<hex>" format.

    Returns:
        True if the report_data_hash is consistent with the nonce and context.
    """
    from ._providers import RuntimeAttestationReport as _RRT
    if not isinstance(report, _RRT):
        raise TypeError(f"expected RuntimeAttestationReport, got {type(report).__name__}")

    ctx_bytes = bytes.fromhex(context_hash.split(":", 1)[-1])
    qualifying = hashlib.sha256(nonce + ctx_bytes).digest()
    expected = "sha256:" + hashlib.sha256(qualifying).hexdigest()
    return hmac.compare_digest(report.report_data_hash, expected)


# ---------------------------------------------------------------------------
# Revocation store
# ---------------------------------------------------------------------------


class RevocationStore:
    """In-memory revocation store. Production should use a persistent backend."""

    def __init__(self) -> None:
        self._revoked: dict[str, RevocationRecord] = {}

    def revoke(self, record: RevocationRecord) -> None:
        self._revoked[record.manifest_id] = record

    def is_revoked(self, manifest_id: str) -> bool:
        return manifest_id in self._revoked

    def get_record(self, manifest_id: str) -> Optional[RevocationRecord]:
        return self._revoked.get(manifest_id)


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------


# A manifest is a few kilobytes (envelope spec section 4, which cites size as
# the reason payloads are inline rather than detached). The cap is generous
# against that and small enough that a body is bounded before anything parses
# it - the decoder is never handed an unbounded allocation.
MAX_COSE_ENVELOPE_BYTES = 1 << 20  # 1 MiB


def create_router(
    manifest_store: dict[str, dict[str, Any]],
    revocation_store: RevocationStore,
    cose_context: Optional[VerificationContext] = None,
) -> Any:
    """Return a FastAPI APIRouter with /verify and /revocation-status endpoints.

    Args:
        manifest_store: Dict mapping manifest_id -> manifest dict.
        revocation_store: Revocation store instance.
        cose_context: Trust configuration for ``POST /verify/cose``, held by
            the server rather than accepted from the caller. Omit it and that
            endpoint is fail-closed: every result is ``UNVERIFIABLE``, never
            ``VALID``, exactly as ``GET /verify`` behaves without keys.
    """
    try:
        from fastapi import APIRouter, HTTPException, Query, Request, Response
        from fastapi.responses import JSONResponse  # noqa: F401
    except ImportError:
        raise ImportError(
            "FastAPI is required for the verification endpoint. "
            'Install with: pip install "agent-manifest[server]"'
        )

    router = APIRouter()

    def _lookup_manifest(manifest_id: str) -> dict[str, Any]:
        """Validate manifest_id format and fetch the manifest or raise."""
        from ._types import ManifestId
        try:
            ManifestId._validate(manifest_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error_code="INVALID_MANIFEST_ID",
                    error_message="manifest_id must be a UUID v7",
                ).model_dump(),
            )

        manifest = manifest_store.get(manifest_id)
        if manifest is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="MANIFEST_NOT_FOUND",
                    error_message="The requested manifest was not found.",
                ).model_dump(),
            )
        return manifest

    @router.get("/verify", response_model=VerificationResult)
    async def verify(
        manifest_id: str = Query(..., description="UUID v7 manifest identifier"),
        enforce_hitl: bool = Query(False),
        enforce_attestation: bool = Query(False),
    ) -> VerificationResult:
        """Verify a manifest without caller-supplied key material.

        This endpoint cannot receive trusted keys, so signature verification
        is fail-closed: a signed manifest returns ``UNVERIFIABLE`` and an
        unsigned manifest returns ``SIGNATURE_MISSING`` - never ``VALID``.
        Callers that hold the issuer's public keys MUST use ``POST /verify``
        and supply ``trusted_keys`` to obtain a ``VALID`` result.
        """
        manifest = _lookup_manifest(manifest_id)
        ctx = VerificationContext(
            enforce_hitl=enforce_hitl,
            enforce_attestation=enforce_attestation,
        )
        return verify_manifest(manifest, ctx, revocation_store)

    @router.post("/verify", response_model=VerificationResult)
    async def verify_post(request: VerifyRequest) -> VerificationResult:
        """Verify a manifest with caller-supplied trusted keys.

        The request body carries ``trusted_keys`` (key_id -> base64url public
        key) used for manifest signature verification, optionally
        ``trusted_key_issuers`` (key_id -> issuer SPIFFE URIs) for key issuer
        authorization, and optionally ``delegation_public_keys`` (principal_id
        -> base64url public key) for delegation chain verification.
        Verification is fail-closed - see :func:`verify_manifest`.
        """
        manifest = _lookup_manifest(request.manifest_id)
        ctx = VerificationContext(
            enforce_hitl=request.enforce_hitl,
            enforce_attestation=request.enforce_attestation,
            trusted_keys=request.trusted_keys,
            trusted_key_issuers=request.trusted_key_issuers,
            delegation_public_keys=request.delegation_public_keys,
            require_delegation=request.require_delegation,
        )
        return verify_manifest(manifest, ctx, revocation_store)

    async def verify_cose(
        request: "Request",
        response: "Response",
        enforce_hitl: bool = Query(False),
        enforce_attestation: bool = Query(False),
    ) -> VerificationResult:
        """Verify a version 0.2 COSE manifest submitted as raw CBOR.

        The body is the ``COSE_Sign1`` or ``COSE_Sign`` object itself, sent as
        ``Content-Type: application/agent-manifest+cose``. The manifest is
        self-contained - the payload travels inside the signature - so unlike
        the other endpoints there is nothing to look up and no
        ``manifest_id`` to trust from the caller.

        Three deliberate choices, each of which is a security property rather
        than a convenience:

        **The media type is the gate.** Only the exact registered type is
        accepted. A vendor-tree alias is refused (envelope spec section 7:
        two valid type values for one object is the ambiguity ``typ`` exists
        to remove), and so is an absent or guessed type - the server never
        sniffs the body to decide what it is.

        **No key material crosses the wire.** Trust comes from
        ``cose_context``, configured server-side when the router is built.
        A verification service that accepts caller-supplied trusted keys is
        only as trustworthy as its caller, and public keys in a URL or header
        end up in proxy logs and access logs. Without a configured trust
        store this endpoint returns ``UNVERIFIABLE``, never ``VALID``.

        **The body is bounded before it is parsed.** ``Content-Length`` is
        checked when present and the stream is capped regardless, because a
        declared length is attacker-controlled and may lie.

        A malformed or unverifiable envelope is a *verdict*, not a transport
        error: the response is 200 with a non-``VALID`` result. Parser detail
        is not reflected back, so this endpoint cannot be used as an oracle
        for how the decoder behaves.

        Authentication, authorization and rate limiting are deployment
        concerns and are deliberately not implemented here; mount this router
        behind them (spec 5.1: mTLS with the agent's SPIFFE SVID).
        """
        media_type = (request.headers.get("content-type") or "").split(";")[0]
        if media_type.strip().lower() != MEDIA_TYPE_MANIFEST_COSE:
            raise HTTPException(
                status_code=415,
                detail=ErrorResponse(
                    error_code="UNSUPPORTED_MEDIA_TYPE",
                    error_message=(
                        f"This endpoint accepts {MEDIA_TYPE_MANIFEST_COSE} only."
                    ),
                ).model_dump(),
            )

        declared_length = request.headers.get("content-length")
        if declared_length is not None:
            try:
                if int(declared_length) > MAX_COSE_ENVELOPE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=ErrorResponse(
                            error_code="ENVELOPE_TOO_LARGE",
                            error_message=(
                                f"A COSE manifest may not exceed "
                                f"{MAX_COSE_ENVELOPE_BYTES} bytes."
                            ),
                        ).model_dump(),
                    )
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=ErrorResponse(
                        error_code="INVALID_CONTENT_LENGTH",
                        error_message="Content-Length is not an integer.",
                    ).model_dump(),
                )

        # Cap the stream too: Content-Length is a claim, not a guarantee.
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > MAX_COSE_ENVELOPE_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail=ErrorResponse(
                        error_code="ENVELOPE_TOO_LARGE",
                        error_message=(
                            f"A COSE manifest may not exceed "
                            f"{MAX_COSE_ENVELOPE_BYTES} bytes."
                        ),
                    ).model_dump(),
                )

        ctx = (cose_context or VerificationContext()).model_copy(
            update={
                "enforce_hitl": enforce_hitl,
                "enforce_attestation": enforce_attestation,
            }
        )
        # A verification result is a security decision about a specific set of
        # bytes at a point in time. It must not be cached or content-sniffed.
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return verify_manifest(bytes(body), ctx, revocation_store)

    # This module uses `from __future__ import annotations`, so annotations are
    # strings, and FastAPI resolves them against the module globals - where
    # `Request` and `Response` do not appear, because fastapi is an optional
    # extra imported inside this function. Binding the real classes before
    # registering the route keeps the import lazy without FastAPI mistaking
    # the two parameters for query parameters.
    verify_cose.__annotations__["request"] = Request
    verify_cose.__annotations__["response"] = Response
    router.add_api_route(
        "/verify/cose",
        verify_cose,
        methods=["POST"],
        response_model=VerificationResult,
    )

    @router.get("/revocation-status")
    async def revocation_status(
        manifest_id: str = Query(...),
    ) -> RevocationRecord:
        # Validate manifest_id to prevent log injection (INJ-005/SEC-009)
        from ._types import ManifestId
        try:
            ManifestId._validate(manifest_id)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=ErrorResponse(
                    error_code="INVALID_MANIFEST_ID",
                    error_message="manifest_id must be a UUID v7",
                ).model_dump(),
            )
        record = revocation_store.get_record(manifest_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=ErrorResponse(
                    error_code="NOT_REVOKED",
                    error_message="The requested manifest has no revocation record.",
                ).model_dump(),
            )
        return record

    return router
