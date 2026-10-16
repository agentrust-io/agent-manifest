#!/usr/bin/env python3
"""Render the paper's result figures from experiments/results/bench.json.

Reads ONLY the real measured numbers written by bench.py; hand-writes nothing.
Emits two PDFs into figures/ (matplotlib -> PDF renders under Tectonic):

    figures/delegation_latency.pdf  E3: verify latency vs delegation depth
    figures/sign_verify_size.pdf    E1/E2: sign/verify latency and size by manifest

Run:
    PYTHONUTF8=1 python experiments/plot.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results" / "bench.json"
FIGDIR = HERE.parent / "figures"
FIGDIR.mkdir(exist_ok=True)

plt.rcParams.update({
    "font.size": 9,
    "figure.dpi": 150,
    "pdf.fonttype": 42,
})

data = json.loads(RESULTS.read_text(encoding="utf-8"))


def plot_delegation() -> None:
    rows = data["delegation"]["rows"]
    depth = [r["depth"] for r in rows]
    median = [r["median_ms"] for r in rows]
    p95 = [r["p95_ms"] for r in rows]
    p99 = [r["p99_ms"] for r in rows]

    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    ax.plot(depth, median, marker="o", color="#1f4e79", label="median", zorder=3)
    ax.fill_between(depth, median, p95, color="#1f4e79", alpha=0.15, label="median to p95")
    ax.plot(depth, p99, marker=".", linestyle="--", color="#c0504d", label="p99", zorder=3)
    ax.set_xlabel("delegation chain depth (hops)")
    ax.set_ylabel("chain verify latency (ms)")
    ax.set_xticks(depth)
    ax.set_ylim(bottom=0)
    ax.grid(True, alpha=0.3, linewidth=0.5)
    ax.legend(frameon=False, loc="upper left", fontsize=8)
    fig.tight_layout()
    out = FIGDIR / "delegation_latency.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"wrote {out}")


def plot_sign_verify_size() -> None:
    sv = data["sign_verify"]
    names = list(sv.keys())
    labels = [n.replace("_", "\n") for n in names]
    sign = [sv[n]["sign"]["median_ms"] for n in names]
    verify = [sv[n]["verify"]["median_ms"] for n in names]
    jcs_kb = [sv[n]["size"]["canonical_jcs_bytes"] / 1024.0 for n in names]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6.6, 3.0))

    x = range(len(names))
    w = 0.38
    ax1.bar([i - w / 2 for i in x], sign, width=w, color="#1f4e79", label="sign")
    ax1.bar([i + w / 2 for i in x], verify, width=w, color="#4f81bd", label="verify")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels, fontsize=7)
    ax1.set_ylabel("median latency (ms)")
    ax1.set_title("(a) sign / verify latency", fontsize=9)
    ax1.grid(True, axis="y", alpha=0.3, linewidth=0.5)
    ax1.legend(frameon=False, fontsize=8)

    ax2.bar(list(x), jcs_kb, width=0.55, color="#9bbb59")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(labels, fontsize=7)
    ax2.set_ylabel("canonical (JCS) size (KiB)")
    ax2.set_title("(b) on-the-wire manifest size", fontsize=9)
    ax2.grid(True, axis="y", alpha=0.3, linewidth=0.5)

    fig.tight_layout()
    out = FIGDIR / "sign_verify_size.pdf"
    fig.savefig(out)
    plt.close(fig)
    print(f"wrote {out}")


if __name__ == "__main__":
    plot_delegation()
    plot_sign_verify_size()
