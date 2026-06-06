"""A2A delegation chain signing and verification — issue #12.

Implements the cryptographic delegation chain primitive from spec Section 3.4.
Each hop is signed by the delegating principal's Ed25519 key over the RFC 8785
canonical form of the hop's scope_grant + metadata. Scope narrowing is enforced:
a child scope may not claim broader permissions than its parent granted.

HITL approval record signing — issue #13.
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


def verify_delegation_chain(
    delegation_chain: list[dict[str, Any]],
    public_keys: dict[str, bytes],  # principal_id -> public key bytes
    manifest_id: str,
) -> None:
    """Verify all hops in a delegation chain.

    Checks:
      - Each hop signature is valid for its principal's key.
      - Hop indices are sequential starting from 0.
      - Scope at each hop is not broader than the previous hop's grant.
      - Chain depth does not exceed root hop's max_delegation_depth.

    Args:
        delegation_chain: List of hop dicts from the manifest.
        public_keys: Map of principal_id -> raw Ed25519 public key bytes.
        manifest_id: Manifest ID to include in pre-image (replay protection).

    Raises:
        InvalidSignature: If any hop signature is invalid.
        ValueError: If scope laundering is detected or chain is malformed.
    """
    if not delegation_chain:
        return

    root_max_depth = delegation_chain[0]["scope_grant"].get("max_delegation_depth", 3)
    # DELEG-002: max_delegation_depth counts sub-delegation levels below the root,
    # so a chain of (root + N delegates) has depth N. Allow length <= max_depth + 1.
    if len(delegation_chain) > root_max_depth + 1:
        raise ValueError(
            f"Delegation chain depth {len(delegation_chain) - 1} exceeds "
            f"root max_delegation_depth {root_max_depth}"
        )

    prev_scope: Optional[dict[str, Any]] = None

    for i, hop in enumerate(delegation_chain):
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
