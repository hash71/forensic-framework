"""Forensic Operations Center -- Home page."""
import streamlit as st
from datetime import datetime
from dashboard_utils import (
    apply_theme, load_all_data, render_page_header, render_page_guide,
    render_sidebar_info, get_incident_list, verdict_badge, severity_dot,
    plotly_layout, tip, SOURCE_TYPE_INFO, INCIDENT_NAMES, _eval_for_scenario,
    SEV_COLORS,
)
import plotly.graph_objects as go

# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------
apply_theme()
data = load_all_data()
render_sidebar_info(data)
render_page_header(
    "Operations Center",
    "Headline view of the 115-scenario forensic corpus. Click any incident to investigate.",
)
render_page_guide(
    "This is the top-level operations view. Headline KPIs (top row) summarise the "
    "entire 115-scenario corpus. The **Connected Servers** strip shows how the seven "
    "unified-schema source types contribute to the event stream. **Detection "
    "Performance** plots rule-baseline vs LLM accuracy side-by-side. The bottom "
    "**Monitored Incidents** table lists every scenario with its rule verdict, LLM "
    "verdict, and ground-truth label — sorted with confirmed attacks first.\n\n"
    "Click *Investigate →* on any row to drill into the per-event timeline, the "
    "LLM's cited evidence, and the seven-check validator's grounding report.",
    glossary=[
        ("Severity dot", "Red = confirmed attack (LLM YES + ground truth ATTACK), yellow = suspicious (rule warnings only or mismatch with ground truth), green = clear (both systems agree it's benign)."),
        ("Rule Verdict column", "NO_ALERT, SUSPICIOUS (warnings only), or ATTACK (one or more critical-severity rules fired)."),
        ("LLM Verdict column", "CLEAR (mapped from NO/INSUFFICIENT) or ATTACK (mapped from YES)."),
        ("Truth column", "Ground-truth label predetermined by scenario design (calibration set) or by the parameterised family it was sampled from (holdout)."),
    ],
)

# ---------------------------------------------------------------------------
# Compute summaries
# ---------------------------------------------------------------------------
eval_results = data.get("evaluation_results", [])
incidents = get_incident_list(data)

sev_order = {"critical": 0, "warning": 1, "clear": 2}
incidents_sorted = sorted(incidents, key=lambda x: (sev_order.get(x["severity"], 9), x["num"]))

# Counts
threats = sum(1 for i in incidents if i["severity"] == "critical")
warnings = sum(1 for i in incidents if i["severity"] == "warning")
clear_count = sum(1 for i in incidents if i["severity"] == "clear")

# Source counts
source_counts = {}
total_events = 0
for num, sc in data["scenarios"].items():
    events = sc.get("events", sc.get("scenario", {}).get("events", []))
    if isinstance(events, list):
        for ev in events:
            st_key = ev.get("source_type", "unknown")
            source_counts[st_key] = source_counts.get(st_key, 0) + 1
            total_events += 1

# Accuracy
rule_correct = sum(1 for r in eval_results if r.get("verdict_accuracy", {}).get("rule_correct"))
llm_correct = sum(1 for r in eval_results if r.get("verdict_accuracy", {}).get("llm_correct"))
total_eval = len(eval_results) or 1
rule_acc = rule_correct / total_eval * 100
llm_acc = llm_correct / total_eval * 100

# ===========================================================================
# A. Key Metrics Row
# ===========================================================================
m1, m2, m3, m4 = st.columns(4)
m1.metric("Servers Connected", 7, delta="All Online", help="Number of server types being monitored (auth, file, admin, network, database, web, email)")
m2.metric("Events Analyzed", f"{total_events:,}", delta="From 7 sources", help="Total log events ingested across all 115 forensic scenarios (15 calibration + 100 holdout)")
m3.metric("Threats Detected", threats, delta=f"{warnings} warnings", help="Incidents where the LLM confirmed an active attack. Warnings indicate suspicious but unconfirmed activity.")
m4.metric("Detection Accuracy", f"{llm_acc:.0f}%", delta=f"+{llm_acc - rule_acc:.0f}% vs Rules", help="LLM verdict accuracy compared to ground truth. Delta shows improvement over the rule engine.")

# ===========================================================================
# B. Connected Servers
# ===========================================================================
st.markdown("---")
st.subheader("Connected Servers")
st.caption("Seven server types generate log events that feed the forensic analysis pipeline.")

server_cols = st.columns(7)
for idx, (src_key, info) in enumerate(SOURCE_TYPE_INFO.items()):
    count = source_counts.get(src_key, 0)
    pct_of_total = count / total_events * 100 if total_events else 0
    with server_cols[idx]:
        st.markdown(
            f"""<div class="server-card tt tt-clean" data-tip="{info['server']}&#10;{count} events ({pct_of_total:.0f}% of total)">
                <span class="server-icon">{info['icon']}</span>
                <div>
                    <div class="server-name">{info['server']}</div>
                    <div class="server-count">{count} events</div>
                </div>
                <div class="server-status"></div>
            </div>""",
            unsafe_allow_html=True,
        )

# ===========================================================================
# C. Detection Performance
# ===========================================================================
st.markdown("---")
st.subheader("Detection Performance")
st.caption(f"Comparing rule-based detection vs LLM analysis across all {total_eval} scenarios. Headline accuracy on the holdout split is reported on the Research page.")

perf_left, perf_right = st.columns(2)

with perf_left:
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=["Rule Engine", "LLM (Gemma)"],
        y=[rule_acc, llm_acc],
        text=[f"{rule_acc:.0f}%", f"{llm_acc:.0f}%"],
        textposition="outside",
        marker_color=["#94a3b8", "#2563eb"],
        width=0.5,
    ))
    fig.update_layout(**plotly_layout(
        title="Verdict Accuracy (%)",
        yaxis=dict(range=[0, 110], gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
        height=350,
    ))
    st.plotly_chart(fig, use_container_width=True)

with perf_right:
    st.markdown(f"""
The LLM correctly classified **{llm_correct}/{total_eval}** scenarios compared to **{rule_correct}/{total_eval}** for the rule engine across the full corpus.

**The headline splits sharply by label.** On the 100-scenario holdout, the LLM reaches 100% accuracy on attacks (statistically established, *p* < 0.001) but only 51% on benigns. On the 34 *hard-benign* scenarios designed to fire alerts, it falls to 38%.

**Forensic role:** The LLM is best characterised as a high-recall first-pass triage layer that contributes recall on subtle multi-day insider patterns rules miss, with a real false-positive cost on legitimate-but-noisy activity. It is not an autonomous detector.
""")

# ===========================================================================
# D. Monitored Incidents
# ===========================================================================
st.markdown("---")
st.subheader("Monitored Incidents")
st.caption(f"{total_eval} forensic scenarios analyzed (15 calibration + {max(0, total_eval - 15)} holdout). Red = confirmed attack, green = cleared, yellow = suspicious. Click to investigate.")

# Header row
hdr = st.columns([0.5, 1, 3, 2, 2, 1.5, 2])
hdr[0].markdown(tip("**Sev**", "Severity level: red=attack confirmed, yellow=suspicious, green=clear"), unsafe_allow_html=True)
hdr[1].markdown(tip("**ID**", f"Scenario identifier (S01–S{total_eval:02d}). S01–S15 are the calibration set; S16+ are the generator-created holdout."), unsafe_allow_html=True)
hdr[2].markdown(tip("**Incident**", "Type of forensic scenario being investigated"), unsafe_allow_html=True)
hdr[3].markdown(tip("**Rule Verdict**", "Rule engine classification based on alert thresholds (R001–R012)"), unsafe_allow_html=True)
hdr[4].markdown(tip("**LLM Verdict**", "LLM analyst classification (open-weight Gemma, temperature 0.1)"), unsafe_allow_html=True)
hdr[5].markdown(tip("**Truth**", "Ground truth label from scenario design (calibration) or family parameters (holdout)"), unsafe_allow_html=True)
hdr[6].markdown("**Action**")

# Incident rows
for inc in incidents_sorted:
    ev_rec = _eval_for_scenario(data, inc["num"])
    rule_verdict = ev_rec.get("rule_verdict", "--") if ev_rec else "--"
    rv_display = rule_verdict.replace("_", " ").upper()
    rv_colors = {"attack": "#ef4444", "suspicious": "#f59e0b", "no_alert": "#22c55e"}
    rv_color = rv_colors.get(rule_verdict, "#475569")

    num = inc["num"]
    cols = st.columns([0.5, 1, 3, 2, 2, 1.5, 2])
    cols[0].markdown(severity_dot(inc["severity"]), unsafe_allow_html=True)
    cols[1].markdown(f"S{num:02d}")
    display_name = inc["name"]
    if num == 15:
        display_name = f"⚠ {display_name}"
        cols[2].markdown(tip(display_name, "LLM false positive — classified legitimate end-of-quarter bulk activity as an attack. Ablation-confirmed rule-context amplification (see Research page)."), unsafe_allow_html=True)
    elif num == 2:
        display_name = f"⚠ {display_name}"
        cols[2].markdown(tip(display_name, "LLM false positive — classified Singapore business-travel activity as an attack. Also the source of the single invalid citation observed across all 115 scenarios (a sentence placed in an evidence-id slot)."), unsafe_allow_html=True)
    else:
        cols[2].markdown(display_name)
    cols[3].markdown(f'<span style="color:{rv_color};font-weight:600;">{rv_display}</span>', unsafe_allow_html=True)
    cols[4].markdown(verdict_badge(inc["verdict"]), unsafe_allow_html=True)
    cols[5].markdown(inc["label"])
    with cols[6]:
        if st.button("Investigate →", key=f"inv_{num}", use_container_width=True):
            st.session_state.selected_incident = num
            st.switch_page("pages/1_Investigation.py")
