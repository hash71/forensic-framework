#!/usr/bin/env python3
"""Regenerate the figures referenced by conference_paper/paper.tex.

Currently emits:
    conference_paper/figures/fig8_verdict_matrix.pdf
        Per-family accuracy on the holdout corpus, rules vs Gemma, with
        Clopper-Pearson 95% CI error bars. Replaces the old 15-cell
        per-scenario matrix, which doesn't scale to 115.

    conference_paper/figures/fig10_calibration_vs_holdout.pdf
        Comparison of calibration (S1-S15) vs holdout (S16-S115) accuracy.

Inputs:
    data/statistics_report.json (produced by run_statistics.py)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
REPORT_PATH = PROJECT_ROOT / "data" / "statistics_report.json"
OUT_DIR = PROJECT_ROOT.parent / "conference_paper" / "figures"


def _load_report() -> dict:
    with open(REPORT_PATH, "r") as f:
        return json.load(f)


def _save(fig, out_path: Path) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, bbox_inches="tight")
    print(f"wrote {out_path}")


def family_chart(report: dict, out_path: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    families = sorted(report["family_breakdown"].keys())
    if not families:
        print("no family data; skipping family chart")
        return
    rule_acc = [report["family_breakdown"][f]["rule"]["value"]
                for f in families]
    rule_lo = [report["family_breakdown"][f]["rule"]["ci_lo"]
               for f in families]
    rule_hi = [report["family_breakdown"][f]["rule"]["ci_hi"]
               for f in families]
    llm_acc = [report["family_breakdown"][f]["llm"]["value"]
               for f in families]
    llm_lo = [report["family_breakdown"][f]["llm"]["ci_lo"]
              for f in families]
    llm_hi = [report["family_breakdown"][f]["llm"]["ci_hi"]
              for f in families]

    x = np.arange(len(families))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    ax.bar(x - width / 2,
           [100 * v for v in rule_acc], width, label="Rules",
           yerr=[[100 * (v - lo) for v, lo in zip(rule_acc, rule_lo)],
                  [100 * (hi - v) for v, hi in zip(rule_acc, rule_hi)]],
           capsize=3, color="#888888", edgecolor="black")
    ax.bar(x + width / 2,
           [100 * v for v in llm_acc], width, label="Gemma",
           yerr=[[100 * (v - lo) for v, lo in zip(llm_acc, llm_lo)],
                  [100 * (hi - v) for v, hi in zip(llm_acc, llm_hi)]],
           capsize=3, color="#4477aa", edgecolor="black")
    ax.set_xticks(x)
    ax.set_xticklabels([f.replace("_", "\n") for f in families],
                       rotation=0, fontsize=8)
    ax.set_ylabel("Verdict accuracy (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Per-family accuracy on holdout corpus (95% CI)",
                  fontsize=10)
    ax.axhline(50, ls="--", lw=0.5, color="grey")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    _save(fig, out_path)
    plt.close(fig)


def calibration_vs_holdout(report: dict, out_path: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    slices = ["calibration", "holdout"]
    labels = ["Calibration (S1–15)", "Holdout (S16–115)"]
    rule_acc = [report["accuracy_by_slice"][s]["rule"]["value"] or 0
                 for s in slices]
    rule_err = [[(rule_acc[i] - report["accuracy_by_slice"][s]["rule"]["ci_lo"])
                  for i, s in enumerate(slices)],
                 [(report["accuracy_by_slice"][s]["rule"]["ci_hi"] - rule_acc[i])
                  for i, s in enumerate(slices)]]
    llm_acc = [report["accuracy_by_slice"][s]["llm"]["value"] or 0
                for s in slices]
    llm_err = [[(llm_acc[i] - report["accuracy_by_slice"][s]["llm"]["ci_lo"])
                 for i, s in enumerate(slices)],
                [(report["accuracy_by_slice"][s]["llm"]["ci_hi"] - llm_acc[i])
                 for i, s in enumerate(slices)]]

    fig, ax = plt.subplots(figsize=(6.0, 3.2))
    x = np.arange(len(slices))
    width = 0.35
    ax.bar(x - width / 2, [100 * v for v in rule_acc], width, label="Rules",
           yerr=[[100 * e for e in rule_err[0]],
                  [100 * e for e in rule_err[1]]],
           capsize=4, color="#888888", edgecolor="black")
    ax.bar(x + width / 2, [100 * v for v in llm_acc], width, label="Gemma",
           yerr=[[100 * e for e in llm_err[0]],
                  [100 * e for e in llm_err[1]]],
           capsize=4, color="#4477aa", edgecolor="black")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Verdict accuracy (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Calibration vs holdout accuracy (95% CI)", fontsize=10)
    ax.legend(loc="upper right", fontsize=9)
    fig.tight_layout()
    _save(fig, out_path)
    plt.close(fig)


def cert_vs_synthetic(report: dict, out_path: Path) -> None:
    """Bar chart: rules vs Gemma on (holdout synthetic) vs (CERT real-data),
    with 95% CI error bars."""
    import matplotlib.pyplot as plt
    import numpy as np

    cert = report.get("cert", {})
    if not cert or not cert.get("n"):
        print("no CERT data; skipping cert_vs_synthetic chart")
        return
    slices = ["holdout", "cert"]
    labels = ["Synthetic\nholdout", "CERT r4.2\nreal-data"]
    rule_acc, rule_lo, rule_hi = [], [], []
    llm_acc, llm_lo, llm_hi = [], [], []
    for s in slices:
        if s == "cert":
            r = cert["rule"]; l = cert["llm"]
        else:
            r = report["accuracy_by_slice"][s]["rule"]
            l = report["accuracy_by_slice"][s]["llm"]
        rule_acc.append(r["value"] or 0)
        rule_lo.append((r["value"] or 0) - (r["ci_lo"] or 0))
        rule_hi.append((r["ci_hi"] or 0) - (r["value"] or 0))
        llm_acc.append(l["value"] or 0)
        llm_lo.append((l["value"] or 0) - (l["ci_lo"] or 0))
        llm_hi.append((l["ci_hi"] or 0) - (l["value"] or 0))
    fig, ax = plt.subplots(figsize=(6.0, 3.2))
    x = np.arange(len(slices))
    w = 0.35
    ax.bar(x - w / 2, [100 * v for v in rule_acc], w, label="Rules",
           yerr=[[100 * e for e in rule_lo], [100 * e for e in rule_hi]],
           capsize=4, color="#888888", edgecolor="black")
    ax.bar(x + w / 2, [100 * v for v in llm_acc], w, label="Gemma",
           yerr=[[100 * e for e in llm_lo], [100 * e for e in llm_hi]],
           capsize=4, color="#4477aa", edgecolor="black")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Verdict accuracy (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Generalisation: synthetic holdout vs CERT r4.2 (95% CI)",
                  fontsize=10)
    ax.legend(loc="upper right", fontsize=9)
    fig.tight_layout()
    _save(fig, out_path)
    plt.close(fig)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()

    report = _load_report()
    family_chart(report, args.out_dir / "fig8_verdict_matrix.pdf")
    calibration_vs_holdout(report,
                            args.out_dir / "fig10_calibration_vs_holdout.pdf")
    cert_vs_synthetic(report, args.out_dir / "fig11_cert_vs_synthetic.pdf")
    return 0


if __name__ == "__main__":
    sys.exit(main())
