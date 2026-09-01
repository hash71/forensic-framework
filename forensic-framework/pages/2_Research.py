"""Research Findings — Rule-based vs LLM comparison across 15 forensic scenarios."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import plotly.graph_objects as go

from dashboard_utils import (
    apply_theme, load_all_data, render_page_header, render_sidebar_info,
    plotly_layout, tip, INCIDENT_NAMES, _eval_for_scenario,
    get_scenario_description, get_ground_truth_info,
)

apply_theme()
data = load_all_data()
render_sidebar_info(data)
render_page_header(
    "Research Findings",
    "Comparing rule-based detection vs LLM analysis (Qwen 3.5-27B) across 15 forensic investigation scenarios.",
)

eval_results = data.get("evaluation_results", [])

# ─────────────────────────────────────────────────────────────────────────────
# Section A — The Headline Result
# ─────────────────────────────────────────────────────────────────────────────

st.subheader("Why LLM analysis outperforms traditional rules")

col_llm, col_rule = st.columns(2)
with col_llm:
    st.metric("LLM Analyst Accuracy", "93%", "14/15 scenarios correct")
with col_rule:
    st.metric("Rule Engine Accuracy", "67%", "10/15 scenarios correct")

st.info(
    "The LLM's advantage comes from contextual reasoning -- understanding user intent, "
    "correlating events across time and sources, and recognizing attack patterns that "
    "static threshold-based rules miss. The LLM correctly identified 4 additional attacks "
    "that rules could not detect."
)

# ─────────────────────────────────────────────────────────────────────────────
# Section B — Where Rules Fail (5 scenarios)
# ─────────────────────────────────────────────────────────────────────────────

st.subheader("Where Rules Fail")
st.caption(
    "The rule engine failed on 5 scenarios. Each reveals a fundamental limitation "
    "of threshold-based detection."
)

RULE_FAILURE_REASONS = {
    5: (
        "Rules saw suspicious activity but could not confirm it was a hijack because "
        "session hijacking requires understanding that the IP changed mid-session. "
        "Rules only check individual event thresholds and cannot correlate session "
        "continuity across IP addresses."
    ),
    6: (
        "Rules flagged after-hours activity as an attack, but it was legitimate "
        "maintenance. Rules cannot distinguish legitimate after-hours work from "
        "malicious activity because they rely solely on time-of-day thresholds "
        "without understanding operational context."
    ),
    10: (
        "Log aggregation delay caused network events to appear 2 hours before auth "
        "events. Rules could not reconcile out-of-order timestamps and failed to "
        "reconstruct the true attack sequence from delayed log delivery."
    ),
    12: (
        "The VPN connection timestamp was AFTER file access -- a fabricated VPN log. "
        "Rules could not detect the timestamp anomaly as evidence of log manipulation "
        "because they evaluate events independently without cross-source consistency checks."
    ),
    13: (
        "Data exfiltration occurred at 1 file per day for 7 days. Each day looks "
        "normal individually. Rules check short windows and completely missed the "
        "week-long low-and-slow exfiltration pattern."
    ),
}

rule_failures = [
    r for r in eval_results
    if not r.get("verdict_accuracy", {}).get("rule_correct", True)
]

for r in rule_failures:
    sn = r["scenario"]
    name = INCIDENT_NAMES.get(sn, f"S{sn}")
    truth = r["ground_truth_label"]
    rv = r["rule_verdict"].replace("_", " ").upper()
    gt_info = get_ground_truth_info(data, sn)
    challenge = gt_info.get("challenge", "")
    description = get_scenario_description(data, sn)

    with st.expander(f"S{sn:02d} -- {name}: Rules said {rv}, truth was {truth}"):
        st.markdown(f"**Scenario:** {description}")
        if challenge:
            st.warning(f"**Challenge:** {challenge}")
        reason = RULE_FAILURE_REASONS.get(sn, "The rule engine could not handle this scenario's complexity.")
        st.markdown(f"**Why rules failed:** {reason}")

# ─────────────────────────────────────────────────────────────────────────────
# Section C — The One LLM Failure (S15)
# ─────────────────────────────────────────────────────────────────────────────

st.subheader("Where the LLM Failed")
st.caption("The LLM incorrectly classified one benign scenario as an attack.")

gt15 = get_ground_truth_info(data, 15)
desc15 = get_scenario_description(data, 15)

st.warning(
    "**S15 -- End-of-Quarter Bulk**: The LLM saw high-volume downloads, late-night activity, "
    "and cross-department file access -- patterns that closely mimic data exfiltration. "
    "However, this was legitimate end-of-quarter reporting. The LLM was overcautious, "
    "demonstrating that even contextual AI can be fooled by benign activity that strongly "
    "resembles attacks."
)

# ─────────────────────────────────────────────────────────────────────────────
# Section D — Stress Tests (tabbed)
# ─────────────────────────────────────────────────────────────────────────────

st.subheader("Stress Testing")
st.caption(
    "Four stress tests evaluated the LLM's resilience to degraded, noisy, and malformed input data."
)

stress = data.get("stress_tests", {})

tab_removal, tab_noise, tab_jitter, tab_format = st.tabs(
    ["Evidence Removal", "Noise Injection", "Temporal Jitter", "Format Resilience"]
)

# --- Tab 1: Evidence Removal (test_b) ---
with tab_removal:
    st.caption(
        "What happens when evidence is progressively deleted? Simulates incomplete forensic data."
    )
    test_b = stress.get("test_b", [])
    if test_b:
        # Group by removal_pct, compute accuracy per group
        from collections import defaultdict
        pct_groups = defaultdict(list)
        for rec in test_b:
            pct_groups[rec["removal_pct"]].append(rec.get("correct", False))

        # Sort by numeric percentage
        def _pct_sort(p):
            return int(p.replace("%", ""))

        sorted_pcts = sorted(pct_groups.keys(), key=_pct_sort)
        x_vals = [p for p in sorted_pcts]
        y_vals = [sum(v) / len(v) * 100 for v in (pct_groups[p] for p in sorted_pcts)]

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=x_vals, y=y_vals,
            mode="lines+markers",
            line=dict(color="#2563eb", width=2),
            marker=dict(size=8, color="#2563eb"),
            name="Accuracy",
        ))
        fig.update_layout(**plotly_layout(
            title="LLM Accuracy vs Evidence Removal",
            xaxis_title="Evidence Removed",
            yaxis_title="Accuracy %",
            yaxis=dict(range=[0, 105], gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
            xaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
            height=360,
        ))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No evidence removal stress test data available.")

# --- Tab 2: Noise Injection (test_c) ---
with tab_noise:
    st.caption(
        "Can the LLM maintain accuracy when flooded with irrelevant noise events?"
    )
    test_c = stress.get("test_c", [])
    if test_c:
        rows_html = ""
        for rec in test_c:
            correct = rec.get("correct", False)
            result_color = "#16a34a" if correct else "#dc2626"
            result_text = "PASS" if correct else "FAIL"
            verdict = rec.get("verdict", "?")
            rows_html += (
                f"<tr>"
                f"<td>{rec.get('ratio', '-')}</td>"
                f"<td>{rec.get('total_events', '-')}</td>"
                f"<td>{rec.get('noise_events', '-')}</td>"
                f"<td style='color:{result_color};font-weight:700'>{result_text}</td>"
                f"<td>{verdict}</td>"
                f"</tr>"
            )
        st.markdown(
            f"""<table class="cmp-table">
            <thead><tr>
                <th>Ratio</th><th>Total Events</th><th>Noise Events</th>
                <th>Result</th><th>Verdict</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
            </table>""",
            unsafe_allow_html=True,
        )
    else:
        st.info("No noise injection stress test data available.")

# --- Tab 3: Temporal Jitter (test_d) ---
with tab_jitter:
    st.caption(
        "How does the LLM handle out-of-order timestamps caused by log collection delays?"
    )
    test_d = stress.get("test_d", [])
    if test_d:
        rows_html = ""
        for rec in test_d:
            correct = rec.get("correct", False)
            result_color = "#16a34a" if correct else "#dc2626"
            tl = rec.get("timeline_correct", False)
            tl_color = "#16a34a" if tl else "#dc2626"
            co = rec.get("chain_order_ok", False)
            co_color = "#16a34a" if co else "#dc2626"
            rows_html += (
                f"<tr>"
                f"<td>{rec.get('jitter', '-')}</td>"
                f"<td>{rec.get('verdict', '-')}</td>"
                f"<td style='color:{tl_color};font-weight:700'>{'YES' if tl else 'NO'}</td>"
                f"<td style='color:{co_color};font-weight:700'>{'YES' if co else 'NO'}</td>"
                f"</tr>"
            )
        st.markdown(
            f"""<table class="cmp-table">
            <thead><tr>
                <th>Jitter Amount</th><th>Verdict</th>
                <th>Timeline Correct</th><th>Chain Order</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
            </table>""",
            unsafe_allow_html=True,
        )
    else:
        st.info("No temporal jitter stress test data available.")

# --- Tab 4: Format Resilience (test_a) ---
with tab_format:
    st.caption(
        "Does the LLM work with raw unprocessed logs as well as the full normalized pipeline?"
    )
    test_a = stress.get("test_a", [])
    if test_a:
        rows_html = ""
        for rec in test_a:
            correct = rec.get("correct", False)
            result_color = "#16a34a" if correct else "#dc2626"
            result_text = "PASS" if correct else "FAIL"
            rows_html += (
                f"<tr>"
                f"<td>{rec.get('mode', '-')}</td>"
                f"<td>{rec.get('verdict', '-')}</td>"
                f"<td>{rec.get('recall', '-')}</td>"
                f"<td>{rec.get('hallucinations', '-')}</td>"
                f"</tr>"
            )
        st.markdown(
            f"""<table class="cmp-table">
            <thead><tr>
                <th>Format Mode</th><th>Verdict</th>
                <th>Recall</th><th>Hallucinations</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
            </table>""",
            unsafe_allow_html=True,
        )
    else:
        st.info("No format resilience stress test data available.")

# ─────────────────────────────────────────────────────────────────────────────
# Section E — Full Comparison Matrix
# ─────────────────────────────────────────────────────────────────────────────

st.subheader("Detailed Comparison Matrix")
st.caption(
    "Complete results for all 15 scenarios. PASS means the method's verdict matched ground truth."
)

if eval_results:
    header = (
        "<tr>"
        f"<th>{tip('ID', 'Scenario identifier')}</th>"
        f"<th>{tip('Scenario', 'Incident scenario name')}</th>"
        f"<th>{tip('Truth', 'Ground truth label (ATTACK or BENIGN)')}</th>"
        f"<th>{tip('Rule Verdict', 'Rule engine raw classification')}</th>"
        f"<th>{tip('LLM Verdict', 'LLM raw verdict (YES/NO)')}</th>"
        f"<th>{tip('Rule Result', 'PASS = matches truth, FAIL = wrong')}</th>"
        f"<th>{tip('LLM Result', 'PASS = matches truth, FAIL = wrong')}</th>"
        f"<th>{tip('R.Precision', 'Rule precision: TP/(TP+FP)')}</th>"
        f"<th>{tip('L.Precision', 'LLM precision: TP/(TP+FP)')}</th>"
        f"<th>{tip('R.F1', 'Rule F1: harmonic mean of precision and recall')}</th>"
        f"<th>{tip('L.F1', 'LLM F1: harmonic mean of precision and recall')}</th>"
        f"<th>{tip('FP%', 'False positive rate: % benign events incorrectly flagged')}</th>"
        "</tr>"
    )

    rows_html = ""
    for r in sorted(eval_results, key=lambda x: x.get("scenario", 0)):
        sn = r["scenario"]
        name = INCIDENT_NAMES.get(sn, f"Scenario {sn}")
        truth = r.get("ground_truth_label", "?")
        rv = r.get("rule_verdict", "?").replace("_", " ").upper()
        lv = r.get("llm_verdict", "?")

        va = r.get("verdict_accuracy", {})
        rule_ok = va.get("rule_correct", False)
        llm_ok = va.get("llm_correct", False)

        rule_color = "#16a34a" if rule_ok else "#dc2626"
        rule_text = "PASS" if rule_ok else "FAIL"
        llm_color = "#16a34a" if llm_ok else "#dc2626"
        llm_text = "PASS" if llm_ok else "FAIL"

        prec = r.get("precision", {})
        rp = prec.get("rule_precision")
        lp = prec.get("llm_precision")
        rp_str = f"{rp:.0%}" if rp is not None else "-"
        lp_str = f"{lp:.0%}" if lp is not None else "-"

        f1 = r.get("f1", {})
        rf1 = f1.get("rule_f1")
        lf1 = f1.get("llm_f1")
        rf1_str = f"{rf1:.2f}" if rf1 is not None else "-"
        lf1_str = f"{lf1:.2f}" if lf1 is not None else "-"

        fp = r.get("false_positives", {})
        fp_rate = fp.get("false_positive_rate_pct", 0.0)
        fp_str = f"{fp_rate:.1f}%"

        rows_html += (
            f"<tr>"
            f"<td>S{sn:02d}</td>"
            f"<td>{name}</td>"
            f"<td>{truth}</td>"
            f"<td>{rv}</td>"
            f"<td>{lv}</td>"
            f"<td style='color:{rule_color};font-weight:700'>{rule_text}</td>"
            f"<td style='color:{llm_color};font-weight:700'>{llm_text}</td>"
            f"<td>{rp_str}</td>"
            f"<td>{lp_str}</td>"
            f"<td>{rf1_str}</td>"
            f"<td>{lf1_str}</td>"
            f"<td>{fp_str}</td>"
            f"</tr>"
        )

    st.markdown(
        f"""<table class="cmp-table">
        <thead>{header}</thead>
        <tbody>{rows_html}</tbody>
        </table>""",
        unsafe_allow_html=True,
    )
else:
    st.info("No evaluation results available.")
