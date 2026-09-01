#!/usr/bin/env python3
"""Compute statistics that survive peer review.

Reads:
    data/evaluation_results.json     -- per-scenario rule/LLM verdicts
    data/ground_truth/ground_truth.json -- labels + holdout/family flags
    data/corpus_manifest.json        -- family/hard_benign breakdown
    data/variance_runs.json (opt)    -- N=5 repeated runs

Writes:
    data/statistics_report.json      -- machine-readable numbers
    data/statistics_table.tex        -- LaTeX-ready accuracy table

Computes:
  1. Verdict accuracy per system per slice with exact Clopper-Pearson 95% CIs.
     Slices: all / holdout-only / calibration-only / benign-only /
             attack-only / per-family / hard-benign-only.
  2. McNemar exact test, rules vs LLM, on the holdout corpus.
  3. Bootstrap (10k resamples) CIs for accuracy deltas and citation validity.
  4. Run-to-run variance from N=5 subset: per-scenario verdict flip rate
     and Fleiss' kappa.
  5. Grounding metrics: invalid-citation rate with CI, chronology violations,
     per hallucination-type counts.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

import numpy as np
from scipy.stats import beta, binom


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
EVALUATION_PATH = DATA_DIR / "evaluation_results.json"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth" / "ground_truth.json"
MANIFEST_PATH = DATA_DIR / "corpus_manifest.json"
VARIANCE_PATH = DATA_DIR / "variance_runs.json"
REPORT_PATH = DATA_DIR / "statistics_report.json"
TABLE_PATH = DATA_DIR / "statistics_table.tex"


# ---------------------------------------------------------------------------
# Confidence intervals
# ---------------------------------------------------------------------------

def clopper_pearson(successes: int, trials: int, alpha: float = 0.05
                     ) -> tuple[float, float]:
    """Exact Clopper-Pearson two-sided CI for a binomial proportion.

    Implementation via the Beta-distribution inverse. Handles the two
    boundary cases (0 and n successes) where the standard formula has a
    degenerate term.
    """
    if trials == 0:
        return 0.0, 1.0
    if successes == 0:
        lower = 0.0
    else:
        lower = beta.ppf(alpha / 2, successes, trials - successes + 1)
    if successes == trials:
        upper = 1.0
    else:
        upper = beta.ppf(1 - alpha / 2, successes + 1, trials - successes)
    return float(lower), float(upper)


def proportion_summary(successes: int, trials: int) -> dict:
    """Return a {value, n, k, ci_lo, ci_hi} record for one proportion."""
    if trials == 0:
        return {"value": None, "n": 0, "k": 0, "ci_lo": None, "ci_hi": None}
    p = successes / trials
    lo, hi = clopper_pearson(successes, trials)
    return {
        "value": p, "n": trials, "k": successes,
        "ci_lo": lo, "ci_hi": hi,
    }


# ---------------------------------------------------------------------------
# McNemar exact test
# ---------------------------------------------------------------------------

def mcnemar_exact(b: int, c: int) -> dict:
    """Two-sided exact McNemar p-value.

    b = pairs where system A correct, B wrong
    c = pairs where system A wrong, B correct
    Under H0 of equal accuracy, b ~ Binomial(b+c, 0.5).
    """
    n = b + c
    if n == 0:
        return {"b": b, "c": c, "p_value": 1.0, "n_discordant": 0}
    k = min(b, c)
    # Two-sided exact: 2 * P(X <= k) for k <= (b+c)/2
    p = 2 * binom.cdf(k, n, 0.5)
    p = min(p, 1.0)
    return {"b": b, "c": c, "p_value": float(p), "n_discordant": n}


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def bootstrap_diff(
    rule_correct: list[bool], llm_correct: list[bool],
    n_resamples: int = 10_000, seed: int = 1234, alpha: float = 0.05,
) -> dict:
    """Bootstrap 95% CI for (LLM accuracy - rule accuracy) — paired bootstrap.

    Each resample draws indices with replacement, recomputes both system
    accuracies on the resampled set, and tracks the per-resample delta.
    """
    assert len(rule_correct) == len(llm_correct)
    n = len(rule_correct)
    if n == 0:
        return {"delta": None, "ci_lo": None, "ci_hi": None,
                "n_resamples": 0}
    rng = np.random.default_rng(seed)
    rule_arr = np.asarray(rule_correct, dtype=bool)
    llm_arr = np.asarray(llm_correct, dtype=bool)
    deltas = np.empty(n_resamples, dtype=float)
    for i in range(n_resamples):
        idx = rng.integers(0, n, size=n)
        deltas[i] = llm_arr[idx].mean() - rule_arr[idx].mean()
    lo = float(np.quantile(deltas, alpha / 2))
    hi = float(np.quantile(deltas, 1 - alpha / 2))
    observed = float(llm_arr.mean() - rule_arr.mean())
    return {
        "delta": observed, "ci_lo": lo, "ci_hi": hi,
        "n_resamples": n_resamples,
    }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _load_evaluation() -> list[dict]:
    with open(EVALUATION_PATH, "r") as f:
        return json.load(f)


def _load_ground_truth() -> dict[str, dict]:
    with open(GROUND_TRUTH_PATH, "r") as f:
        doc = json.load(f)
    return {e["id"]: e for e in doc["scenarios"]}


def _load_manifest_index() -> dict[str, dict]:
    if not MANIFEST_PATH.exists():
        return {}
    with open(MANIFEST_PATH, "r") as f:
        doc = json.load(f)
    return {m["scenario_id"]: m for m in doc.get("scenarios", [])}


# ---------------------------------------------------------------------------
# Slicing
# ---------------------------------------------------------------------------

def _slice_label(ev: dict, gt_idx: dict, mf_idx: dict, slice_name: str) -> bool:
    sid = f"scenario_{ev['scenario']}"
    gt = gt_idx.get(sid, {})
    mf = mf_idx.get(sid, {})
    if slice_name == "all":
        return True
    if slice_name == "holdout":
        return bool(gt.get("holdout", False))
    if slice_name == "calibration":
        return not gt.get("holdout", False)
    if slice_name == "benign":
        return gt.get("label") == "BENIGN"
    if slice_name == "attack":
        return gt.get("label") == "ATTACK"
    if slice_name == "hard_benign":
        return bool(mf.get("hard_benign", False))
    if slice_name == "holdout_benign":
        return gt.get("holdout", False) and gt.get("label") == "BENIGN"
    if slice_name == "holdout_attack":
        return gt.get("holdout", False) and gt.get("label") == "ATTACK"
    if slice_name.startswith("family_"):
        return mf.get("family") == slice_name.removeprefix("family_")
    raise ValueError(f"Unknown slice: {slice_name}")


def _accuracies(evs: list[dict], system: str) -> tuple[int, int]:
    """Return (correct, total) for a system over a list of evaluations."""
    correct = sum(
        1 for e in evs
        if e.get("verdict_accuracy", {}).get(f"{system}_correct", False)
    )
    return correct, len(evs)


def _correct_vector(evs: list[dict], system: str) -> list[bool]:
    return [bool(e.get("verdict_accuracy", {}).get(f"{system}_correct", False))
            for e in evs]


# ---------------------------------------------------------------------------
# Per-family breakdown
# ---------------------------------------------------------------------------

def _family_breakdown(evs: list[dict], mf_idx: dict) -> dict:
    by_family: dict[str, list[dict]] = defaultdict(list)
    for e in evs:
        fam = mf_idx.get(f"scenario_{e['scenario']}", {}).get("family")
        if fam:
            by_family[fam].append(e)
    out = {}
    for fam, evs_f in by_family.items():
        rule_k, n = _accuracies(evs_f, "rule")
        llm_k, _ = _accuracies(evs_f, "llm")
        out[fam] = {
            "n": n,
            "rule": proportion_summary(rule_k, n),
            "llm": proportion_summary(llm_k, n),
        }
    return out


# ---------------------------------------------------------------------------
# Variance (N=5 repeated runs)
# ---------------------------------------------------------------------------

def _fleiss_kappa(matrix: np.ndarray) -> float:
    """Fleiss' kappa for n items rated by m raters into k categories.

    `matrix` is (n_items, n_categories) with each row summing to n_raters.
    """
    n_items, n_cat = matrix.shape
    n_raters = matrix.sum(axis=1)
    if not np.allclose(n_raters, n_raters[0]):
        raise ValueError("All items must have the same number of raters")
    m = float(n_raters[0])
    if n_items == 0 or m <= 1:
        return float("nan")
    p_j = matrix.sum(axis=0) / (n_items * m)
    P_i = (np.sum(matrix * matrix, axis=1) - m) / (m * (m - 1))
    P_bar = P_i.mean()
    P_e = float(np.sum(p_j ** 2))
    if P_e >= 1.0:
        return 1.0
    return float((P_bar - P_e) / (1 - P_e))


def _variance_block(variance: list[dict]) -> dict:
    """Compute flip rate + Fleiss' kappa across N repeated runs.

    `variance` shape: [
        {"scenario": N, "runs": ["YES", "YES", "NO", ...]},
        ...
    ]
    """
    if not variance:
        return {"n_scenarios": 0, "flip_rate": None, "fleiss_kappa": None}
    n_items = len(variance)
    cats = ["YES", "NO", "INSUFFICIENT"]
    matrix = np.zeros((n_items, len(cats)), dtype=float)
    flips = 0
    for i, item in enumerate(variance):
        runs = item.get("runs", [])
        for r in runs:
            r = r.upper() if isinstance(r, str) else "INSUFFICIENT"
            if r not in cats:
                r = "INSUFFICIENT"
            matrix[i, cats.index(r)] += 1
        if len(set(runs)) > 1:
            flips += 1
    flip_rate = flips / n_items
    kappa = _fleiss_kappa(matrix)
    return {
        "n_scenarios": n_items,
        "flip_rate": flip_rate,
        "fleiss_kappa": kappa,
        "category_counts": {c: int(matrix[:, j].sum())
                             for j, c in enumerate(cats)},
    }


# ---------------------------------------------------------------------------
# Grounding metrics
# ---------------------------------------------------------------------------

def _grounding_block(evs: list[dict]) -> dict:
    """Aggregate validator outputs across scenarios."""
    total_refs = 0
    valid_refs = 0
    chronology_violations = 0
    type_counts: Counter[str] = Counter()
    scenarios_with_invalid = 0
    for e in evs:
        h = e.get("hallucination_report", {})
        if not h:
            continue
        evt = h.get("event_references", {})
        total_refs += evt.get("total_references", 0)
        valid_refs += evt.get("valid_references", 0)
        if evt.get("invalid_references"):
            scenarios_with_invalid += 1
        if not h.get("timeline_correctness", {}).get("chronologically_correct", True):
            chronology_violations += 1
        # The hallucination_report has counts per check; tally any non-zero.
        for k, v in h.items():
            if isinstance(v, dict) and "violations" in v:
                if v.get("violations"):
                    type_counts[k] += 1
    n = len(evs)
    invalid_rate = (n - scenarios_with_invalid) / n if n else None
    return {
        "n_scenarios": n,
        "total_event_references": total_refs,
        "valid_event_references": valid_refs,
        "citation_validity":
            proportion_summary(valid_refs, total_refs) if total_refs else None,
        "scenarios_with_zero_invalid":
            proportion_summary(n - scenarios_with_invalid, n),
        "chronology_violations": chronology_violations,
        "violation_type_counts": dict(type_counts),
    }


# ---------------------------------------------------------------------------
# LaTeX table emission
# ---------------------------------------------------------------------------

def _latex_table(report: dict) -> str:
    """Emit a LaTeX-ready accuracy table (lines for slice × system)."""
    slices = ["all", "holdout", "calibration", "holdout_benign",
              "holdout_attack", "hard_benign"]
    lines = [
        r"% Auto-generated. Source: run_statistics.py",
        r"\begin{tabular}{lrrrrr}",
        r"\toprule",
        r"Slice & N & Rules acc (95\% CI) & Gemma acc (95\% CI) & "
        r"$\Delta$ (Gemma$-$Rules) & McNemar $p$ \\",
        r"\midrule",
    ]
    for s in slices:
        row = report["accuracy_by_slice"].get(s)
        if not row or row["rule"]["n"] == 0:
            continue
        rule = row["rule"]
        llm = row["llm"]
        delta = report["bootstrap_delta"].get(s, {})
        mc = report["mcnemar"].get(s, {})

        def fmt(p):
            v, lo, hi = p["value"], p["ci_lo"], p["ci_hi"]
            if v is None:
                return "--"
            return f"{v*100:.1f}\\% ({lo*100:.1f}, {hi*100:.1f})"

        delta_str = ("--" if delta.get("delta") is None else
                      f"{delta['delta']*100:+.1f}\\% "
                      f"({delta['ci_lo']*100:+.1f}, {delta['ci_hi']*100:+.1f})")
        mc_str = ("--" if mc.get("p_value") is None
                   else f"{mc['p_value']:.3f}")
        lines.append(
            f"{s.replace('_', r' ')} & {rule['n']} & {fmt(rule)} & "
            f"{fmt(llm)} & {delta_str} & {mc_str} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

CERT_RESULTS_PATH = DATA_DIR / "evaluation_results_cert.json"


def _load_cert_results() -> list[dict]:
    if not CERT_RESULTS_PATH.exists():
        return []
    with open(CERT_RESULTS_PATH, "r") as f:
        return json.load(f)


def _cert_block(cert: list[dict]) -> dict:
    """Compute the CERT-specific stat block (accuracy, McNemar, grounding,
    per-insider-scenario-type breakdown). Mirrors the synthetic-slice fields.
    """
    if not cert:
        return {"n": 0}
    rc = [r["verdict_accuracy"]["rule_correct"] for r in cert]
    lc = [r["verdict_accuracy"]["llm_correct"] for r in cert]
    n = len(cert)
    rule_k = sum(rc); llm_k = sum(lc)
    b = sum(1 for r, l in zip(rc, lc) if r and not l)
    c = sum(1 for r, l in zip(rc, lc) if not r and l)
    by_label = {"BENIGN": [], "ATTACK": []}
    for r in cert:
        by_label[r["ground_truth_label"]].append(r)
    out = {
        "n": n,
        "rule": proportion_summary(rule_k, n),
        "llm": proportion_summary(llm_k, n),
        "mcnemar": mcnemar_exact(b, c),
        "bootstrap_delta": bootstrap_diff(rc, lc),
    }
    for label, subset in by_label.items():
        if not subset:
            continue
        srk = sum(r["verdict_accuracy"]["rule_correct"] for r in subset)
        slk = sum(r["verdict_accuracy"]["llm_correct"] for r in subset)
        out[label.lower()] = {
            "n": len(subset),
            "rule": proportion_summary(srk, len(subset)),
            "llm": proportion_summary(slk, len(subset)),
        }
    # Per-insider-scenario-type breakdown (1 / 2 / 3 / None)
    by_type: dict[str, list[dict]] = defaultdict(list)
    for r in cert:
        t = r.get("scenario_meta", {}).get("ground_truth_scenario_type")
        key = f"insider_scenario_{t}" if t else "benign"
        by_type[key].append(r)
    out["by_scenario_type"] = {
        k: {
            "n": len(v),
            "rule": proportion_summary(
                sum(x["verdict_accuracy"]["rule_correct"] for x in v),
                len(v),
            ),
            "llm": proportion_summary(
                sum(x["verdict_accuracy"]["llm_correct"] for x in v),
                len(v),
            ),
        }
        for k, v in sorted(by_type.items())
    }
    # Grounding aggregation (mirrors _grounding_block but uses cert records)
    total_refs = valid_refs = chronology_violations = 0
    scenarios_with_invalid = 0
    for r in cert:
        h = r.get("hallucination_report", {}) or {}
        evt = h.get("event_references", {}) or {}
        total_refs += evt.get("total_references", 0)
        valid_refs += evt.get("valid_references", 0)
        if evt.get("invalid_references"):
            scenarios_with_invalid += 1
        if not h.get("timeline_correctness", {}).get(
                "chronologically_correct", True):
            chronology_violations += 1
    out["grounding"] = {
        "n_scenarios": n,
        "total_event_references": total_refs,
        "valid_event_references": valid_refs,
        "citation_validity":
            proportion_summary(valid_refs, total_refs) if total_refs else None,
        "scenarios_with_zero_invalid":
            proportion_summary(n - scenarios_with_invalid, n),
        "chronology_violations": chronology_violations,
    }
    # Multi-day insider recall question (Q2): for ATTACK scenarios spanning
    # multiple days, was the LLM correct?
    multi_day_recall = []
    for r in cert:
        if r["ground_truth_label"] != "ATTACK":
            continue
        meta = r.get("scenario_meta", {})
        ev_count = meta.get("event_count", 0)
        if ev_count >= 30:  # rough proxy for multi-day activity
            multi_day_recall.append(
                r["verdict_accuracy"]["llm_correct"]
            )
    if multi_day_recall:
        out["multi_day_attack_recall"] = proportion_summary(
            sum(multi_day_recall), len(multi_day_recall),
        )
    return out


def run(eval_path: Path = EVALUATION_PATH) -> dict:
    evs = _load_evaluation()
    gt_idx = _load_ground_truth()
    mf_idx = _load_manifest_index()

    slices = ["all", "holdout", "calibration", "benign", "attack",
              "holdout_benign", "holdout_attack", "hard_benign"]
    # Add per-family slices for whatever families exist
    families = sorted({m.get("family") for m in mf_idx.values()
                       if m.get("family")})
    slices += [f"family_{f}" for f in families]

    accuracy_by_slice: dict[str, dict] = {}
    bootstrap_delta: dict[str, dict] = {}
    mcnemar: dict[str, dict] = {}

    for s in slices:
        subset = [e for e in evs if _slice_label(e, gt_idx, mf_idx, s)]
        rule_k, n = _accuracies(subset, "rule")
        llm_k, _ = _accuracies(subset, "llm")
        accuracy_by_slice[s] = {
            "n": n,
            "rule": proportion_summary(rule_k, n),
            "llm": proportion_summary(llm_k, n),
        }
        rc = _correct_vector(subset, "rule")
        lc = _correct_vector(subset, "llm")
        bootstrap_delta[s] = bootstrap_diff(rc, lc)
        b = sum(1 for r, l in zip(rc, lc) if r and not l)
        c = sum(1 for r, l in zip(rc, lc) if not r and l)
        mcnemar[s] = mcnemar_exact(b, c)

    # Variance: optional
    variance_block = {"n_scenarios": 0, "flip_rate": None,
                      "fleiss_kappa": None}
    if VARIANCE_PATH.exists():
        with open(VARIANCE_PATH, "r") as f:
            variance_block = _variance_block(json.load(f))

    grounding_all = _grounding_block(evs)
    grounding_holdout = _grounding_block(
        [e for e in evs if _slice_label(e, gt_idx, mf_idx, "holdout")]
    )

    family_breakdown = _family_breakdown(evs, mf_idx)

    cert = _load_cert_results()
    cert_block = _cert_block(cert)

    report = {
        "model": "fusion-gemma",
        "n_scenarios": len(evs),
        "n_calibration": sum(
            1 for e in evs if _slice_label(e, gt_idx, mf_idx, "calibration")
        ),
        "n_holdout": sum(
            1 for e in evs if _slice_label(e, gt_idx, mf_idx, "holdout")
        ),
        "accuracy_by_slice": accuracy_by_slice,
        "bootstrap_delta": bootstrap_delta,
        "mcnemar": mcnemar,
        "family_breakdown": family_breakdown,
        "variance": variance_block,
        "grounding_all": grounding_all,
        "grounding_holdout": grounding_holdout,
        "cert": cert_block,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute accuracy, McNemar, bootstrap, and grounding stats.",
    )
    parser.add_argument("--eval", type=Path, default=EVALUATION_PATH)
    parser.add_argument("--out", type=Path, default=REPORT_PATH)
    parser.add_argument("--tex", type=Path, default=TABLE_PATH)
    args = parser.parse_args()

    report = run(args.eval)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    with open(args.tex, "w") as f:
        f.write(_latex_table(report))

    # Stdout summary
    print(f"model: {report['model']}")
    print(f"scenarios: {report['n_scenarios']} "
          f"(calibration={report['n_calibration']}, "
          f"holdout={report['n_holdout']})")
    print()
    for s in ["all", "calibration", "holdout"]:
        a = report["accuracy_by_slice"].get(s, {})
        rule = a.get("rule", {}); llm = a.get("llm", {})
        mc = report["mcnemar"].get(s, {})
        if rule.get("n"):
            print(f"  {s}: n={rule['n']}, "
                  f"rules={rule['value']*100:.1f}% "
                  f"[{rule['ci_lo']*100:.1f},{rule['ci_hi']*100:.1f}], "
                  f"gemma={llm['value']*100:.1f}% "
                  f"[{llm['ci_lo']*100:.1f},{llm['ci_hi']*100:.1f}], "
                  f"McNemar p={mc.get('p_value', 0):.3f}")
    print(f"\nWrote {args.out}")
    print(f"Wrote {args.tex}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
