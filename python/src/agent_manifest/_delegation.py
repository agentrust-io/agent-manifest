"""A2A delegation chain signing and verification - issue #12.

Implements the cryptographic delegation chain primitive from spec Section 3.4.
Each hop is signed by the delegating principal's Ed25519 key over the RFC 8785
canonical form of the hop's scope_grant + metadata. Scope narrowing is enforced:
a child scope may not claim broader permissions than its parent granted.

HITL approval record signing - issue #13.
Each approval is signed by the approver's Ed25519 key (hardware-backed in
production; software key in development). The approval covers the canonical
form of approved_scope + manifest_id + approved_at.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ._canonicalize import canonicalize
from ._signing import Ed25519KeyPair, Ed25519Verifier

# ---------------------------------------------------------------------------
# A2A Delegation chain
# ---------------------------------------------------------------------------


# Spec 3.4.1: when max_delegation_depth is omitted from a scope_grant,
# verifying parties MUST apply a default value of 3.
DEFAULT_MAX_DELEGATION_DEPTH = 3

# A2A spec §4.2 / agent-manifest spec §3.4: allowed principal_type values.
# The Pydantic ``PrincipalType`` enum in ``models`` is the single source of
# truth (it is what the JSON schema gate enforces). We derive the validator's
# set from that enum rather than duplicating a literal so the two can never
# drift. The import is deferred because ``models`` imports this module at load
# time; importing it at module top level here would create a cycle.
def _valid_principal_types() -> frozenset[str]:
    """Allowed ``principal_type`` values, derived from ``PrincipalType``."""
    from .models import PrincipalType

    return frozenset(member.value for member in PrincipalType)


def __getattr__(name: str) -> Any:
    # Expose ``VALID_PRINCIPAL_TYPES`` as a lazily-derived module attribute so
    # it stays in lockstep with the ``PrincipalType`` enum.
    if name == "VALID_PRINCIPAL_TYPES":
        return _valid_principal_types()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# Required fields per delegation hop (A2A spec §4.2 / agent-manifest spec §3.4).
_REQUIRED_HOP_FIELDS = frozenset({
    "hop", "principal_id", "principal_type", "delegated_at",
    "scope_grant", "delegation_signature",
})
_SCOPE_LIST_FIELDS = ("tools", "data_classifications", "constraints")


def _is_json_integer(value: Any) -> bool:
    """True for JSON-Schema integer values, excluding Python booleans."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and value.is_integer()


def delegation_depth_exceeded(chain_length: int, root_max_depth: int) -> bool:
    """Single depth rule shared by the Pydantic models and this verifier.

    Spec 3.4/3.4.1 semantics: hops are 0-indexed from the root, so the depth
    of a chain is the number of sub-delegation hops below the root, i.e.
    ``chain_length - 1``. ``max_delegation_depth: 0`` on the root scope_grant
    means no further delegation is permitted (a single root hop is still
    valid). A chain is rejected when its depth exceeds the root scope_grant's
    ``max_delegation_depth``.
    """
    return chain_length - 1 > root_max_depth


def _hop_pre_image(
    hop: int,
    principal_id: str,
    principal_type: str,
    delegated_at: str,
    scope_grant: dict[str, Any],
    manifest_id: str,
) -> bytes:
    """RFC 8785 canonical bytes covering the delegation hop content.

    The pre-image includes the hop index and manifest_id to prevent
    cross-manifest delegation replay attacks.
    """
    obj = {
        "hop": hop,
        "manifest_id": manifest_id,
        "principal_id": principal_id,
        "principal_type": principal_type,
        "delegated_at": delegated_at,
        "scope_grant": scope_grant,
    }
    return canonicalize(obj)


@dataclass
class DelegationHopSigner:
    """Signs a single delegation hop."""

    keypair: Ed25519KeyPair

    def sign_hop(
        self,
        *,
        hop: int,
        principal_id: str,
        principal_type: str,
        delegated_at: str,
        scope_grant: dict[str, Any],
        manifest_id: str,
    ) -> str:
        """Return base64url-encoded signature over the hop's canonical pre-image."""
        import base64
        pre = _hop_pre_image(hop, principal_id, principal_type, delegated_at, scope_grant, manifest_id)
        sig_bytes = self.keypair.private_key.sign(pre)
        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()


def _validate_scope_structure(scope: Any, hop_index: int) -> None:
    """Establish the scope types this verifier reads before interpreting them."""
    if not isinstance(scope, dict):
        raise ValueError(
            f"Delegation hop {hop_index} scope_grant must be an object, "
            f"got {type(scope).__name__}"
        )

    for field in _SCOPE_LIST_FIELDS:
        value = scope.get(field, [])
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(
                f"Delegation hop {hop_index} scope_grant.{field} must be a list of strings"
            )

    depth = scope.get("max_delegation_depth", DEFAULT_MAX_DELEGATION_DEPTH)
    if not _is_json_integer(depth) or depth < 0:
        raise ValueError(
            f"Delegation hop {hop_index} scope_grant.max_delegation_depth "
            "must be a non-negative integer"
        )

    ttl = scope.get("ttl_seconds")
    if ttl is not None and (not _is_json_integer(ttl) or ttl < 1):
        raise ValueError(
            f"Delegation hop {hop_index} scope_grant.ttl_seconds "
            "must be a positive integer or null"
        )


def _validate_hop_structure(hop: Any, hop_index: int) -> None:
    """Raise ValueError for structural A2A conformance violations.

    Establishes the shapes and primitive types this verifier reads before
    cryptographic verification or scope interpretation, so malformed peer data
    stays inside the documented ``ValueError`` rejection boundary.
    """
    if not isinstance(hop, dict):
        raise ValueError(
            f"Delegation hop {hop_index} must be an object, got {type(hop).__name__}"
        )

    missing = _REQUIRED_HOP_FIELDS - hop.keys()
    if missing:
        raise ValueError(
            f"Delegation hop {hop_index} missing required fields: {sorted(missing)}"
        )

    hop_value = hop["hop"]
    if not _is_json_integer(hop_value):
        raise ValueError(
            f"Delegation hop {hop_index} hop must be a JSON integer, "
            f"got {type(hop_value).__name__}"
        )

    principal_type = hop["principal_type"]
    valid_principal_types = _valid_principal_types()
    if not isinstance(principal_type, str) or principal_type not in valid_principal_types:
        raise ValueError(
            f"Delegation hop {hop_index} has invalid principal_type {principal_type!r}; "
            f"must be one of {sorted(valid_principal_types)}"
        )

    # principal_id must be non-empty string (SPIFFE URI, DID, or mailto)
    principal_id = hop["principal_id"]
    if not isinstance(principal_id, str) or not principal_id.strip():
        raise ValueError(
            f"Delegation hop {hop_index} has empty or non-string principal_id"
        )

    delegated_at = hop["delegated_at"]
    if not isinstance(delegated_at, str):
        raise ValueError(
            f"Delegation hop {hop_index} delegated_at must be a string"
        )

    principal_manifest_id = hop.get("principal_manifest_id")
    if principal_manifest_id is not None and not isinstance(principal_manifest_id, str):
        raise ValueError(
            f"Delegation hop {hop_index} principal_manifest_id must be a string when present"
        )

    if not isinstance(hop["delegation_signature"], str):
        raise ValueError(
            f"Delegation hop {hop_index} delegation_signature must be a string"
        )

    _validate_scope_structure(hop["scope_grant"], hop_index)


def verify_delegation_chain(
    delegation_chain: list[dict[str, Any]],
    public_keys: dict[str, bytes],  # principal_id -> public key bytes
    manifest_id: str,
    manifest_issuer: str | None = None,
) -> None:
    """Verify all hops in a delegation chain.

    Checks:
      - The chain root is bound to the manifest's signing identity (when
        ``manifest_issuer`` is supplied).
      - Each hop signature is valid for its principal's key.
      - Hop indices are sequential starting from 0.
      - Scope at each hop is not broader than the previous hop's grant
        (tools, data_classifications, constraints, ttl_seconds, depth).
      - Chain depth does not exceed root hop's max_delegation_depth.

    Args:
        delegation_chain: List of hop dicts from the manifest.
        public_keys: Map of principal_id -> raw Ed25519 public key bytes.
        manifest_id: Manifest ID to include in pre-image (replay protection).
        manifest_issuer: The manifest's signing identity (issuer or agent_id).
            When provided, the root hop's principal MUST equal this identity;
            otherwise the chain is rejected. A chain whose root is not the
            manifest signer could be grafted onto an unrelated manifest, so
            this binding is fail-closed when an issuer is known.

    Raises:
        InvalidSignature: If any hop signature is invalid.
        ValueError: If scope laundering is detected or chain is malformed.
    """
    if not isinstance(delegation_chain, list):
        raise ValueError(
            f"delegation_chain must be a list, got {type(delegation_chain).__name__}"
        )
    if not delegation_chain:
        return

    # The root is interpreted before the verification loop, so establish its
    # structure before the root-binding and depth reads below.
    _validate_hop_structure(delegation_chain[0], 0)

    # Bind the chain root to the manifest's signing identity. The root hop
    # establishes the authority the rest of the chain narrows from, so it must
    # originate from the same principal that signed the manifest. Match either
    # principal_id or principal_manifest_id so SPIFFE-keyed and manifest-keyed
    # roots are both accepted.
    if manifest_issuer:
        root = delegation_chain[0]
        root_identities = {
            root.get("principal_id"),
            root.get("principal_manifest_id"),
        }
        if manifest_issuer not in root_identities:
            raise ValueError(
                "Delegation chain root principal "
                f"{root.get('principal_id')!r} does not match the manifest "
                f"signing identity {manifest_issuer!r}; the chain is not bound "
                "to the manifest issuer"
            )

    root_max_depth = delegation_chain[0]["scope_grant"].get(
        "max_delegation_depth", DEFAULT_MAX_DELEGATION_DEPTH
    )
    # DELEG-002: one shared rule - see delegation_depth_exceeded above.
    if delegation_depth_exceeded(len(delegation_chain), root_max_depth):
        raise ValueError(
            f"Delegation chain depth {len(delegation_chain) - 1} exceeds "
            f"root max_delegation_depth {root_max_depth}"
        )

    prev_scope: dict[str, Any] | None = None
    prev_delegated_at: str | None = None

    for i, hop in enumerate(delegation_chain):
        if i:
            _validate_hop_structure(hop, i)

        if hop.get("hop") != i:
            raise ValueError(f"Hop {i} has wrong hop index: {hop.get('hop')}")

        # Verify signature
        principal_id = hop["principal_id"]
        pub_bytes = public_keys.get(principal_id)
        if pub_bytes is None:
            raise ValueError(f"No public key for principal {principal_id!r}")

        pre = _hop_pre_image(
            hop=i,
            principal_id=principal_id,
            principal_type=hop["principal_type"],
            delegated_at=hop["delegated_at"],
            scope_grant=hop["scope_grant"],
            manifest_id=manifest_id,
        )

        import base64
        sig = hop["delegation_signature"]
        pad = 4 - len(sig) % 4
        sig_bytes = base64.urlsafe_b64decode(sig + ("=" * pad if pad != 4 else ""))
        verifier = Ed25519Verifier(pub_bytes)
        verifier._pub.verify(sig_bytes, pre)  # raises InvalidSignature on failure

        # Scope narrowing check
        scope = hop["scope_grant"]
        delegated_at = hop["delegated_at"]
        if prev_scope is not None:
            _check_scope_narrowing(
                prev_scope,
                scope,
                hop_index=i,
                parent_delegated_at=prev_delegated_at,
                child_delegated_at=delegated_at,
            )

        prev_scope = scope
        prev_delegated_at = delegated_at


def _parse_delegated_at(value: str) -> datetime:
    """Parse a hop's ``delegated_at`` ISO 8601 timestamp (accepts a 'Z' suffix).

    A timestamp with no offset is treated as UTC rather than left naive: hops in
    one chain are written by different parties and need not agree on whether to
    include one, and comparing a naive against an aware datetime raises
    TypeError, which is not a refusal.
    """
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _check_scope_narrowing(
    parent: dict[str, Any],
    child: dict[str, Any],
    hop_index: int,
    *,
    parent_delegated_at: str | None = None,
    child_delegated_at: str | None = None,
) -> None:
    """Raise ValueError if child scope is broader than parent scope."""
    parent_tools = set(parent.get("tools") or [])
    child_tools = set(child.get("tools") or [])
    if not parent_tools:
        # Empty parent tools = unrestricted; child may specify any subset
        pass
    else:
        # DELEG-003/DELEG-004: empty child tools with non-empty parent is scope escalation.
        # Child claiming no restriction when parent has explicit restrictions is not allowed.
        if not child_tools:
            raise ValueError(
                f"Scope laundering at hop {hop_index}: "
                f"child claims unrestricted tools (empty list) but parent grants only {parent_tools!r}"
            )
        if not child_tools.issubset(parent_tools):
            extra = child_tools - parent_tools
            raise ValueError(
                f"Scope laundering at hop {hop_index}: "
                f"child claims tools {extra!r} not granted by parent"
            )

    parent_classes = set(parent.get("data_classifications") or [])
    child_classes = set(child.get("data_classifications") or [])
    # DELEG-003: empty parent data_classifications means "none granted",
    # so a child claiming any classification is a scope escalation.
    if not parent_classes and child_classes:
        raise ValueError(
            f"Scope laundering at hop {hop_index}: "
            f"child claims data_classifications {child_classes!r} but parent grants none"
        )
    if parent_classes and child_classes and not child_classes.issubset(parent_classes):
        extra = child_classes - parent_classes
        raise ValueError(
            f"Scope laundering at hop {hop_index}: "
            f"child claims data_classifications {extra!r} not granted by parent"
        )

    # Constraints are restrictions, so narrowing means the child MUST keep
    # every parent constraint and may only add more. Dropping a parent
    # constraint widens the grant and is rejected.
    parent_constraints = set(parent.get("constraints") or [])
    child_constraints = set(child.get("constraints") or [])
    dropped = parent_constraints - child_constraints
    if dropped:
        raise ValueError(
            f"Scope laundering at hop {hop_index}: "
            f"child drops parent constraints {dropped!r}; child constraints "
            "must be a superset of the parent's"
        )

    # ttl_seconds: a child may not live longer than its parent. Absent (None)
    # means unbounded; a child claiming unbounded under a bounded parent, or a
    # larger bound, widens the grant.
    parent_ttl = parent.get("ttl_seconds")
    child_ttl = child.get("ttl_seconds")
    if parent_ttl is not None and (child_ttl is None or child_ttl > parent_ttl):
        raise ValueError(
            f"Scope laundering at hop {hop_index}: "
            f"child ttl_seconds {child_ttl!r} exceeds parent ttl_seconds "
            f"{parent_ttl!r}"
        )
    # DELEG-005: ttl_seconds is a *duration measured from that hop's own*
    # delegated_at, not from a shared origin. Comparing the two durations in
    # isolation (above) is not sufficient: a child hop delegated partway
    # through its parent's window can carry a duration that does not exceed
    # the parent's, yet its absolute expiry (its own delegated_at + its own
    # ttl_seconds) can still fall *after* the parent's absolute expiry
    # (parent's delegated_at + parent's ttl_seconds) - the grant would then
    # outlive the authority it was narrowed from. Comparing the two absolute
    # expiries directly closes this regardless of how far apart the hops'
    # delegated_at timestamps are.
    if (
        parent_ttl is not None
        and child_ttl is not None
        and parent_delegated_at is not None
        and child_delegated_at is not None
    ):
        parent_expiry = _parse_delegated_at(parent_delegated_at) + timedelta(seconds=parent_ttl)
        child_expiry = _parse_delegated_at(child_delegated_at) + timedelta(seconds=child_ttl)
        if child_expiry > parent_expiry:
            raise ValueError(
                f"Scope laundering at hop {hop_index}: child scope_grant "
                f"expires at {child_expiry.isoformat()}, after the parent's "
                f"absolute expiry {parent_expiry.isoformat()}, even though "
                "its ttl_seconds duration does not exceed the parent's "
                "(the child was delegated later, so the same duration "
                "outlives the parent's grant)"
            )

    # max_delegation_depth: a child may not authorize a deeper sub-chain than
    # its parent permitted. Omission defaults to the spec value (3).
    parent_depth = parent.get("max_delegation_depth", DEFAULT_MAX_DELEGATION_DEPTH)
    child_depth = child.get("max_delegation_depth", DEFAULT_MAX_DELEGATION_DEPTH)
    if child_depth > parent_depth:
        raise ValueError(
            f"Scope laundering at hop {hop_index}: "
            f"child max_delegation_depth {child_depth} exceeds parent "
            f"max_delegation_depth {parent_depth}"
        )


# ---------------------------------------------------------------------------
# HITL approval signing
# ---------------------------------------------------------------------------


def _approval_pre_image(
    manifest_id: str,
    approved_at: str,
    approved_scope: dict[str, Any],
    approver_id: str,
) -> bytes:
    """RFC 8785 canonical bytes for HITL approval signing."""
    obj = {
        "manifest_id": manifest_id,
        "approved_at": approved_at,
        "approved_scope": approved_scope,
        "approver_id": approver_id,
    }
    return canonicalize(obj)


@dataclass
class HitlApprovalSigner:
    """Signs a HITL approval record.

    In production, the keypair should be backed by a hardware security key
    (FIDO2/passkey or HSM). The signature proves the approver deliberately
    approved this exact scope at this exact time for this exact manifest.
    """

    keypair: Ed25519KeyPair

    def sign_approval(
        self,
        *,
        manifest_id: str,
        approved_at: str,
        approved_scope: dict[str, Any],
        approver_id: str,
    ) -> str:
        """Return base64url-encoded approval signature."""
        import base64
        pre = _approval_pre_image(manifest_id, approved_at, approved_scope, approver_id)
        sig_bytes = self.keypair.private_key.sign(pre)
        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()


def verify_hitl_approval(
    approval: dict[str, Any],
    manifest_id: str,
    approver_public_key: bytes,
) -> None:
    """Verify a single HITL approval signature.

    Args:
        approval: The approval dict from hitl_record.approvals.
        manifest_id: Manifest ID to bind the approval.
        approver_public_key: Raw Ed25519 public key bytes of the approver.

    Raises:
        InvalidSignature: If the approval signature is invalid.
        ValueError: If required fields are missing, malformed, or the
            approval has expired.
    """
    import base64

    # Establish the shapes this function reads before interpreting them, so a
    # malformed approval always produces the documented ValueError rather than
    # an incidental AttributeError, KeyError, or TypeError from whichever line
    # happens to touch the bad field first.
    if not isinstance(approval, dict):
        raise ValueError(f"HITL approval must be an object, got {type(approval).__name__}")

    for field in ("approved_scope", "approved_at", "approver_id", "approval_signature"):
        if field not in approval:
            raise ValueError(f"HITL approval is missing required field '{field}'")

    approved_scope = approval["approved_scope"]
    if not isinstance(approved_scope, dict):
        raise ValueError(
            f"HITL approval.approved_scope must be an object, got "
            f"{type(approved_scope).__name__}"
        )

    approved_at_str = approval["approved_at"]
    if not isinstance(approved_at_str, str):
        raise ValueError(
            f"HITL approval.approved_at must be a string, got "
            f"{type(approved_at_str).__name__}"
        )

    approver_id = approval["approver_id"]
    if not isinstance(approver_id, str):
        raise ValueError(
            f"HITL approval.approver_id must be a string, got {type(approver_id).__name__}"
        )

    sig = approval["approval_signature"]
    if not isinstance(sig, str):
        raise ValueError(
            f"HITL approval.approval_signature must be a string, got {type(sig).__name__}"
        )

    # HITL-003: enforce approval expiry before verifying signature
    duration = approved_scope.get("approval_duration_seconds", 0)
    if duration:
        if not isinstance(duration, (int, float)):
            raise ValueError(
                f"HITL approval.approved_scope.approval_duration_seconds must be "
                f"numeric, got {type(duration).__name__}"
            )
        try:
            approved_at = datetime.fromisoformat(approved_at_str.replace("Z", "+00:00"))
        except ValueError as e:
            raise ValueError(f"HITL approval has invalid approved_at: {e}") from e
        if datetime.now(timezone.utc) > approved_at + timedelta(seconds=duration):
            raise ValueError(
                f"HITL approval expired: approved_at={approved_at_str}, "
                f"duration={duration}s"
            )

    pre = _approval_pre_image(
        manifest_id=manifest_id,
        approved_at=approved_at_str,
        approved_scope=approved_scope,
        approver_id=approver_id,
    )
    try:
        pad = 4 - len(sig) % 4
        sig_bytes = base64.urlsafe_b64decode(sig + ("=" * pad if pad != 4 else ""))
    except ValueError as e:
        raise ValueError(
            f"HITL approval.approval_signature is not valid base64url: {e}"
        ) from e
    Ed25519Verifier(approver_public_key)._pub.verify(sig_bytes, pre)
