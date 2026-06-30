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
from typing import Any, Optional

from ._canonicalize import canonicalize
from ._signing import Ed25519Verifier, Ed25519KeyPair


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


def _validate_hop_structure(hop: dict[str, Any], hop_index: int) -> None:
    """Raise ValueError for structural A2A conformance violations.

    Validates required fields and principal_type per A2A spec §4.2.
    Called before cryptographic verification so structural errors surface
    as distinct ValueError rather than IndexError or KeyError.
    """
    missing = _REQUIRED_HOP_FIELDS - hop.keys()
    if missing:
        raise ValueError(
            f"Delegation hop {hop_index} missing required fields: {sorted(missing)}"
        )
    principal_type = hop["principal_type"]
    valid_principal_types = _valid_principal_types()
    if principal_type not in valid_principal_types:
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


def verify_delegation_chain(
    delegation_chain: list[dict[str, Any]],
    public_keys: dict[str, bytes],  # principal_id -> public key bytes
    manifest_id: str,
    manifest_issuer: Optional[str] = None,
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
    if not delegation_chain:
        return

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

    prev_scope: Optional[dict[str, Any]] = None

    for i, hop in enumerate(delegation_chain):
        # Structural validation before any field access (raises ValueError on violation)
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
        if prev_scope is not None:
            _check_scope_narrowing(prev_scope, scope, hop_index=i)

        prev_scope = scope


def _check_scope_narrowing(parent: dict[str, Any], child: dict[str, Any], hop_index: int) -> None:
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
        ValueError: If required fields are missing or the approval has expired.
    """
    import base64
    from datetime import datetime, timezone, timedelta

    # HITL-003: enforce approval expiry before verifying signature
    duration = approval.get("approved_scope", {}).get("approval_duration_seconds", 0)
    if duration:
        approved_at_str = approval.get("approved_at", "")
        try:
            approved_at = datetime.fromisoformat(approved_at_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as e:
            raise ValueError(f"HITL approval has invalid approved_at: {e}") from e
        if datetime.now(timezone.utc) > approved_at + timedelta(seconds=duration):
            raise ValueError(
                f"HITL approval expired: approved_at={approved_at_str}, "
                f"duration={duration}s"
            )

    pre = _approval_pre_image(
        manifest_id=manifest_id,
        approved_at=approval["approved_at"],
        approved_scope=approval["approved_scope"],
        approver_id=approval["approver_id"],
    )
    sig = approval["approval_signature"]
    pad = 4 - len(sig) % 4
    sig_bytes = base64.urlsafe_b64decode(sig + ("=" * pad if pad != 4 else ""))
    Ed25519Verifier(approver_public_key)._pub.verify(sig_bytes, pre)
