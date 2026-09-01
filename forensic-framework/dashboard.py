"""Forensic Operations Center -- Home page."""
import streamlit as st
from datetime import datetime
from dashboard_utils import (
    apply_theme, load_all_data, render_page_header, render_sidebar_info,
    get_incident_list, verdict_badge, severity_dot, plotly_layout, tip,
    SOURCE_TYPE_INFO, INCIDENT_NAMES, _eval_for_scenario, SEV_COLORS,
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
    "Monitoring 7 server types across 15 forensic scenarios. Click any incident to investigate.",
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
m2.metric("Events Analyzed", f"{total_events:,}", delta="From 7 sources", help="Total log events ingested across all 15 forensic scenarios")
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
st.caption("Comparing rule-based detection vs LLM analysis across all 15 scenarios.")

perf_left, perf_right = st.columns(2)

with perf_left:
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=["Rule Engine", "LLM (Qwen 3.5-27B)"],
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
The LLM correctly classified **{llm_correct}/15** scenarios compared to **{rule_correct}/15** for the rule engine.

**Where rules fail:** Rules missed 5 scenarios involving subtle insider threats, session hijacks, delayed log events, conflicting signals, and ultra-slow exfiltration — attacks that require contextual reasoning beyond threshold detection.

**LLM advantage:** The LLM correlates events across time and sources, understands user intent, and recognizes patterns that static rules cannot detect.
""")

# ===========================================================================
# D. Monitored Incidents
# ===========================================================================
st.markdown("---")
st.subheader("Monitored Incidents")
st.caption("15 forensic scenarios analyzed. Red = confirmed attack, green = cleared, yellow = suspicious. Click to investigate.")

# Header row
hdr = st.columns([0.5, 1, 3, 2, 2, 1.5, 2])
hdr[0].markdown(tip("**Sev**", "Severity level: red=attack confirmed, yellow=suspicious, green=clear"), unsafe_allow_html=True)
hdr[1].markdown(tip("**ID**", "Scenario identifier (S01–S15)"), unsafe_allow_html=True)
hdr[2].markdown(tip("**Incident**", "Type of forensic scenario being investigated"), unsafe_allow_html=True)
hdr[3].markdown(tip("**Rule Verdict**", "Rule engine classification based on alert thresholds"), unsafe_allow_html=True)
hdr[4].markdown(tip("**LLM Verdict**", "LLM analyst classification (Qwen 3.5-27B)"), unsafe_allow_html=True)
hdr[5].markdown(tip("**Truth**", "Ground truth label from scenario design"), unsafe_allow_html=True)
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
        cols[2].markdown(tip(display_name, "LLM false positive — classified legitimate end-of-quarter activity as an attack"), unsafe_allow_html=True)
    else:
        cols[2].markdown(display_name)
    cols[3].markdown(f'<span style="color:{rv_color};font-weight:600;">{rv_display}</span>', unsafe_allow_html=True)
    cols[4].markdown(verdict_badge(inc["verdict"]), unsafe_allow_html=True)
    cols[5].markdown(inc["label"])
    with cols[6]:
        if st.button("Investigate →", key=f"inv_{num}", use_container_width=True):
            st.session_state.selected_incident = num
            st.switch_page("pages/1_Investigation.py")
