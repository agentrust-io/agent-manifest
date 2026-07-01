"""The delegation verifier is part of the public API.

Downstream projects (for example agentrust-io/cA2A) call this to verify an
inbound peer's delegation chain, so it must be importable from the top-level
package and stable, not reached through the private `_delegation` module.
"""

from __future__ import annotations

import agent_manifest
from agent_manifest import (
    DelegationHopSigner,
    HitlApprovalSigner,
    delegation_depth_exceeded,
    verify_delegation_chain,
    verify_hitl_approval,
)


def test_delegation_symbols_are_public() -> None:
    for name in (
        "verify_delegation_chain",
        "verify_hitl_approval",
        "delegation_depth_exceeded",
        "DelegationHopSigner",
        "HitlApprovalSigner",
    ):
        assert name in agent_manifest.__all__
        assert hasattr(agent_manifest, name)


def test_verify_delegation_chain_callable_on_empty_chain() -> None:
    # An empty chain is a valid no-op (nothing delegated); it must not raise.
    verify_delegation_chain([], {}, manifest_id="m-1")


def test_delegation_depth_exceeded_logic() -> None:
    assert delegation_depth_exceeded(chain_length=5, root_max_depth=3) is True
    assert delegation_depth_exceeded(chain_length=2, root_max_depth=3) is False


def test_signer_classes_importable() -> None:
    assert callable(DelegationHopSigner)
    assert callable(HitlApprovalSigner)
    assert callable(verify_hitl_approval)
