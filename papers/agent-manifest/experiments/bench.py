#!/usr/bin/env python3
"""Agent Manifest benchmark harness.

Produces the real, measured numbers used in the paper. Everything here calls
the agent-manifest SDK in the AGENT_MANIFEST_ROOT checkout
directly. No number is hand-written; every value in results/*.json is printed
by this script.

Schema-valid inputs
-------------------
The manifests benchmarked here are the SDK's own committed example manifests
(AGENT_MANIFEST_ROOT/examples). We do NOT hand-craft manifest
bodies: we load a committed example, strip its placeholder signature, re-sign it
with a freshly generated Ed25519 key, and confirm it verifies VALID before
timing. This guarantees every timed manifest is schema-valid under the shipped
Pydantic models.

Crypto profile
--------------
Only the Ed25519 "standard" profile is measured. The post-quantum ML-DSA-65
profile requires the optional `pyoqs`/`oqs` dependency, which is NOT installed
in this environment (import check at startup records this honestly). No PQ
numbers are produced.

Experiments
-----------
E1  Manifest sign and verify latency (Ed25519 standard profile) across the
    committed example manifests, spanning small (Level 0, 4 artifacts) to full
    (Level 1, 6 artifact bindings + attestation + transparency log). The
    delegation-chain example is exercised separately in E3, where hop
    signatures are freshly produced (its committed placeholder hop signature
    is not verifiable in isolation).
E2  Manifest size on the wire (canonical JCS bytes, compact signed JSON bytes)
    per example manifest.
E3  Delegation-chain verification latency vs chain depth (1..10 hops), built
    with the shipped DelegationHopSigner and monotonic scope narrowing at each
    hop, verified by the shipped verify_delegation_chain.
E4  Tamper detection: mutate each bound artifact / identity field in a signed
    manifest and confirm verification no longer returns VALID.

Run:
    PYTHONUTF8=1 python experiments/bench.py
"""
from __future__ import annotations

import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --- Locate the shipped SDK -------------------------------------------------
SDK_ROOT = Path(os.environ.get("AGENT_MANIFEST_ROOT", "agent-manifest"))
SDK_SRC = SDK_ROOT / "python" / "src"
EXAMPLES = SDK_ROOT / "examples"
if not SDK_SRC.is_dir() or not EXAMPLES.is_dir():
    raise SystemExit("Set AGENT_MANIFEST_ROOT to the historical SDK checkout with python/src and examples.")
if SDK_SRC.is_dir():
    sys.path.insert(0, str(SDK_SRC))

from agent_manifest._canonicalize import canonicalize  # noqa: E402
from agent_manifest._delegation import (  # noqa: E402
    DelegationHopSigner,
    verify_delegation_chain,
)
from agent_manifest._signing import generate_ed25519, Ed25519Signer  # noqa: E402
from agent_manifest._verify import (  # noqa: E402
    OverallResult,
    RevocationStore,
    VerificationContext,
    verify_manifest,
)

# Post-quantum availability probe (honest reporting only; no PQ numbers).
try:
    import oqs  # type: ignore  # noqa: F401

    PQ_AVAILABLE = True
except Exception:
    PQ_AVAILABLE = False

RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)

# Iteration counts: enough for stable medians without a long run.
WARMUP = 50
ITERS = 2000
CHAIN_ITERS = 1000
MAX_DEPTH = 10

# Committed example manifests used as schema-valid inputs, labelled by the
# assurance surface they exercise.
EXAMPLE_MANIFESTS = [
    ("level0", "4 artifacts (software-only)", EXAMPLES / "level0-software-only.json"),
    ("multi_artifact", "5 artifacts + RAG corpus", EXAMPLES / "multi-artifact" / "manifest.json"),
    ("hitl", "4 artifacts + HITL approval", EXAMPLES / "hitl" / "manifest-with-hitl.json"),
    ("level1", "8 artifacts + attestation + tlog", EXAMPLES / "level1-tpm-attested.json"),
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_example(path: Path) -> dict:
    """Load a committed example manifest and strip its placeholder signature."""
    m = json.loads(path.read_text(encoding="utf-8"))
    m.pop("signature", None)
    return m


def _count_artifacts(manifest: dict) -> int:
    return len(manifest.get("artifacts", {}))


# ---------------------------------------------------------------------------
# Signing / verification harness
# ---------------------------------------------------------------------------


def _bench(fn, iters: int) -> list[float]:
    for _ in range(WARMUP):
        fn()
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1e3)  # ms
    return samples


def _summary(samples: list[float]) -> dict:
    s = sorted(samples)
    return {
        "n": len(s),
        "mean_ms": round(statistics.mean(s), 5),
        "median_ms": round(statistics.median(s), 5),
        "p95_ms": round(s[int(0.95 * (len(s) - 1))], 5),
        "p99_ms": round(s[int(0.99 * (len(s) - 1))], 5),
        "min_ms": round(s[0], 5),
        "max_ms": round(s[-1], 5),
    }


def exp_sign_verify() -> dict:
    out = {}
    for name, desc, path in EXAMPLE_MANIFESTS:
        manifest = _load_example(path)
        kp = generate_ed25519()
        signer = Ed25519Signer(kp)
        trusted = {kp.key_id: kp.public_b64url()}
        store = RevocationStore()
        ctx = VerificationContext(trusted_keys=trusted)

        signed = dict(manifest)
        signed["signature"] = signer.sign(manifest)

        # sanity: freshly signed committed example must verify VALID
        r = verify_manifest(signed, ctx, store)
        assert r.signature_verified and r.result == OverallResult.VALID, (
            name,
            r.result,
            [(d.field, d.actual_hash) for d in r.mismatch_details],
        )

        sign_samples = _bench(lambda m=manifest, s=signer: s.sign(m), ITERS)
        verify_samples = _bench(
            lambda s=signed, c=ctx, st=store: verify_manifest(s, c, st), ITERS
        )

        canonical = canonicalize({k: signed[k] for k in signed if k != "signature"})
        signed_bytes = json.dumps(signed, separators=(",", ":")).encode()
        out[name] = {
            "description": desc,
            "sign": _summary(sign_samples),
            "verify": _summary(verify_samples),
            "size": {
                "canonical_jcs_bytes": len(canonical),
                "signed_json_bytes": len(signed_bytes),
                "artifact_bindings": _count_artifacts(signed),
            },
        }
        print(
            f"[E1/E2] {name:15s} n_art={out[name]['size']['artifact_bindings']} "
            f"sign_med={out[name]['sign']['median_ms']:.4f}ms "
            f"verify_med={out[name]['verify']['median_ms']:.4f}ms "
            f"jcs={out[name]['size']['canonical_jcs_bytes']}B "
            f"signed={out[name]['size']['signed_json_bytes']}B"
        )
    return out


# ---------------------------------------------------------------------------
# Delegation chain scaling (shipped DelegationHopSigner + verify_delegation_chain)
# ---------------------------------------------------------------------------

# A fixed pool of tools the root grants; each hop narrows by dropping the last.
_TOOL_POOL = [f"tool:{i:02d}" for i in range(MAX_DEPTH + 2)]
_MANIFEST_ID = "019236ab-0000-7000-8000-000000000011"
_ISSUER = "spiffe://trust.acme.co/signing-authority"


def build_chain(depth: int):
    """Build a signed delegation chain of ``depth`` hops with monotonic scope
    narrowing, plus the principal_id -> pubkey map for the verifier.

    Root principal is the manifest issuer (fail-closed binding). Each hop drops
    one tool from the previous grant, so scope narrows monotonically, and each
    hop signature is produced by the shipped DelegationHopSigner.
    """
    now = _now()
    chain = []
    pubkeys: dict[str, bytes] = {}
    for i in range(depth):
        kp = generate_ed25519()
        principal_id = _ISSUER if i == 0 else f"spiffe://trust.acme.co/agent/hop{i}"
        pubkeys[principal_id] = kp.public_bytes
        # Narrow: root grants the whole pool; each subsequent hop keeps one
        # fewer tool. Depth budget also narrows so the chain stays legal.
        tools = _TOOL_POOL[: len(_TOOL_POOL) - i]
        scope = {
            "tools": tools,
            "data_classifications": ["internal"],
            "max_delegation_depth": MAX_DEPTH - i,
            "constraints": [f"c{j}" for j in range(i + 1)],  # constraints grow (narrowing)
        }
        delegated_at = _iso(now)
        sig = DelegationHopSigner(kp).sign_hop(
            hop=i,
            principal_id=principal_id,
            principal_type="human" if i == 0 else "agent",
            delegated_at=delegated_at,
            scope_grant=scope,
            manifest_id=_MANIFEST_ID,
        )
        chain.append(
            {
                "hop": i,
                "principal_id": principal_id,
                "principal_type": "human" if i == 0 else "agent",
                "delegated_at": delegated_at,
                "scope_grant": scope,
                "delegation_signature": sig,
            }
        )
    return chain, pubkeys, _ISSUER


def exp_delegation_scaling() -> dict:
    rows = []
    for depth in range(1, MAX_DEPTH + 1):
        chain, pubkeys, issuer = build_chain(depth)
        # sanity: the chain must verify (raises on failure)
        verify_delegation_chain(chain, pubkeys, _MANIFEST_ID, manifest_issuer=issuer)
        samples = _bench(
            lambda c=chain, p=pubkeys, iss=issuer: verify_delegation_chain(
                c, p, _MANIFEST_ID, manifest_issuer=iss
            ),
            CHAIN_ITERS,
        )
        summ = _summary(samples)
        rows.append({"depth": depth, **summ})
        print(f"[E3] depth={depth:2d} verify median={summ['median_ms']:.4f}ms")
    return {"iters": CHAIN_ITERS, "rows": rows}


# ---------------------------------------------------------------------------
# Tamper detection (over the committed Level 1 full manifest)
# ---------------------------------------------------------------------------


def _mutate(node_root: dict, path: list[str]) -> dict:
    """Return a deep copy of ``node_root`` with the value at ``path`` mutated to
    a different but well-formed value (a distinct sha256 hash for hash fields,
    or a suffix-appended string otherwise)."""
    import hashlib

    tampered = json.loads(json.dumps(node_root))
    node = tampered
    for k in path[:-1]:
        node = node[k]
    old = node[path[-1]]
    if isinstance(old, str) and old.startswith("sha256:"):
        node[path[-1]] = "sha256:" + hashlib.sha256(("TAMPER:" + old).encode()).hexdigest()
    elif isinstance(old, str):
        node[path[-1]] = old + "-TAMPERED"
    else:
        node[path[-1]] = old
    return tampered


def exp_tamper() -> dict:
    manifest = _load_example(EXAMPLES / "level1-tpm-attested.json")
    kp = generate_ed25519()
    signer = Ed25519Signer(kp)
    trusted = {kp.key_id: kp.public_b64url()}
    store = RevocationStore()
    ctx = VerificationContext(trusted_keys=trusted)

    signed = dict(manifest)
    signed["signature"] = signer.sign(manifest)

    # baseline: untampered signed manifest verifies VALID
    baseline = verify_manifest(signed, ctx, store)
    assert baseline.signature_verified and baseline.result == OverallResult.VALID, (
        baseline.result,
    )

    # Mutate one bound field in turn; re-verify WITHOUT re-signing.
    cases = [
        ("system_prompt.hash", ["artifacts", "system_prompt", "hash"]),
        ("policy_bundle.hash", ["artifacts", "policy_bundle", "hash"]),
        ("tool_manifest.catalog_hash", ["artifacts", "tool_manifest", "catalog_hash"]),
        ("model_identity.version", ["artifacts", "model_identity", "version"]),
        ("decision_trace.audit_chain_root", ["artifacts", "decision_trace", "audit_chain_root"]),
        ("supply_chain.container_image_digest", ["artifacts", "supply_chain", "container_image_digest"]),
        ("agent_id", ["agent_id"]),
        ("issuer", ["issuer"]),
        ("manifest_id", ["manifest_id"]),
        ("issued_at", ["issued_at"]),
    ]
    detected = []
    for label, path in cases:
        tampered = _mutate(signed, path)
        r = verify_manifest(tampered, ctx, store)
        # A tamper is caught iff the manifest no longer returns VALID.
        caught = r.result != OverallResult.VALID
        detected.append(
            {
                "field": label,
                "result": r.result.value,
                "signature_verified": r.signature_verified,
                "caught": caught,
            }
        )
        print(
            f"[E4] tamper {label:38s} -> {r.result.value:16s} "
            f"sig_verified={r.signature_verified} caught={caught}"
        )

    all_caught = all(d["caught"] for d in detected)
    return {"all_caught": all_caught, "n_cases": len(detected), "cases": detected}


def main() -> None:
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "timestamp": _iso(_now()),
        "iters": ITERS,
        "chain_iters": CHAIN_ITERS,
        "warmup": WARMUP,
        "crypto_profile": "standard (Ed25519)",
        "pq_ml_dsa_65_available": PQ_AVAILABLE,
    }
    print("=== Agent Manifest benchmark ===")
    print(json.dumps(env))
    if not PQ_AVAILABLE:
        print("[note] post-quantum ML-DSA-65 deps (oqs/pyoqs) not installed; "
              "only the Ed25519 standard profile is measured.")

    e1e2 = exp_sign_verify()
    e3 = exp_delegation_scaling()
    e4 = exp_tamper()

    results = {"env": env, "sign_verify": e1e2, "delegation": e3, "tamper": e4}
    (RESULTS / "bench.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nWrote {RESULTS / 'bench.json'}")


if __name__ == "__main__":
    main()
