"""Investigation Console — deep-dive into individual incidents."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st
import plotly.express as px
import pandas as pd
from datetime import datetime, timedelta
import re

from dashboard_utils import (
    apply_theme, load_all_data, render_page_header, render_page_guide,
    render_sidebar_info, get_incident_list, verdict_badge, severity_dot,
    plotly_layout, tip, get_scenario_description, get_ground_truth_info,
    _eval_for_scenario, SOURCE_TYPE_INFO, INCIDENT_NAMES, SEV_COLORS,
)

# ── Setup ────────────────────────────────────────────────────────────────────
apply_theme()
data = load_all_data()
render_sidebar_info(data)
render_page_header(
    "Investigation Console",
    "Drill into one incident at a time: ground-truth context, side-by-side verdicts, the cited evidence timeline, and the validator's grounding report.",
)
render_page_guide(
    "Pick a scenario from the selector and the page walks you through the full "
    "investigation: **What Happened** (ground-truth narrative), **Detection "
    "Comparison** (rule engine verdict vs LLM verdict, side by side), **Evidence "
    "Timeline** (chronological Gantt of every cited event), **Event Log** "
    "(filterable raw events), and **Evidence Quality** (the seven-check validator's "
    "report — valid citations, hallucinated event ids, chronology violations).\n\n"
    "Calibration scenarios S01–S15 are the hand-authored set; S16+ are the "
    "generator-created holdout. CERT replays would appear here too, if the "
    "scenarios were copied into `data/scenarios/`.",
    glossary=[
        ("Cited evidence", "An `event_id` listed by the LLM in its `attack_chain`, `evidence_for`, or `evidence_against` arrays. The validator confirms each cited id resolves to a real event in the input timeline."),
        ("Attack chain", "The LLM's ordered narrative of what happened: each step cites the event_id that supports it. Chronology is validated against the cited timestamps."),
        ("Severity dot", "Red = ATTACK verdict, yellow = SUSPICIOUS, green = CLEAR. Sourced from the LLM's mapped verdict for sorting purposes."),
        ("Grounding %", "Fraction of the LLM's narrative that is anchored to a cited event id (vs uncited prose). Higher is more auditable."),
    ],
)

# ── Section A: Incident Selector ─────────────────────────────────────────────

incidents = get_incident_list(data)
_sev_emoji = {"critical": "\U0001f534", "warning": "\U0001f7e1", "clear": "\U0001f7e2"}

# Top filter row: split / family / search \u2014 narrow the dropdown before picking.
filter_cols = st.columns([1.2, 2, 2.5])
with filter_cols[0]:
    split_filter = st.selectbox(
        "Split",
        ["All (115)", "Calibration only (S1\u2013S15)", "Holdout only (S16\u2013S115)"],
        index=0,
        help="Calibration = author-designed. Holdout = generator-created from corpus_spec.yaml under seed 42.",
    )
all_families = sorted({inc["family"] for inc in incidents if inc["family"]})
family_options = ["All families"] + [f.replace("_", " ").title() for f in all_families]
family_lookup = {f.replace("_", " ").title(): f for f in all_families}
with filter_cols[1]:
    family_filter = st.selectbox(
        "Family",
        family_options,
        index=0,
        help="Holdout scenarios were sampled from ten parameterised families. Pick one to narrow to scenarios of the same shape.",
    )
with filter_cols[2]:
    text_filter = st.text_input(
        "Search",
        "",
        placeholder="e.g. S91, hijack, exfil\u2026",
        help="Substring match against scenario id, family, tagline, or label.",
    )


def _passes(inc) -> bool:
    if split_filter.startswith("Calibration") and inc["holdout"]:
        return False
    if split_filter.startswith("Holdout") and not inc["holdout"]:
        return False
    if family_filter != "All families":
        if inc["family"] != family_lookup.get(family_filter):
            return False
    if text_filter.strip():
        q = text_filter.strip().lower()
        hay = " ".join([
            f"s{inc['num']:02d}", inc["name"].lower(), (inc["tagline"] or "").lower(),
            (inc["family"] or "").lower(), inc["label"].lower(),
        ])
        if q not in hay:
            return False
    return True


filtered = [inc for inc in incidents if _passes(inc)]

options = []
option_to_num = {}
for inc in filtered:
    emoji = _sev_emoji.get(inc["severity"], "\u26aa")
    label_tag = inc["label"]
    family_tag = f" \u00b7 {inc['family']}" if (inc["holdout"] and inc["family"]) else ""
    opt = f"{emoji} S{inc['num']:02d} \u2014 {inc['name']}{family_tag} [{label_tag}]"
    options.append(opt)
    option_to_num[opt] = inc["num"]

if not options:
    st.warning("No scenarios match the current filters. Widen the filter or clear the search box.")
    st.stop()

# Find current selection inside the filtered list
current_num = st.session_state.get("selected_incident", filtered[0]["num"])
default_idx = 0
for i, opt in enumerate(options):
    if option_to_num[opt] == current_num:
        default_idx = i
        break
else:
    current_num = filtered[0]["num"]

selected_opt = st.selectbox("Incident", options, index=default_idx, label_visibility="collapsed")
selected_num = option_to_num[selected_opt]

if selected_num != st.session_state.get("selected_incident"):
    st.session_state.selected_incident = selected_num
    st.rerun()

# Tagline card directly under the dropdown \u2014 what is this scenario about?
selected_inc = next((inc for inc in incidents if inc["num"] == selected_num), None)
if selected_inc and selected_inc["tagline"]:
    tagline_html = selected_inc["tagline"]
    if selected_inc["holdout"] and selected_inc["family"]:
        prefix = f"<span style='color:#2563eb;font-weight:600'>Family \u00b7 {selected_inc['family']}</span>"
    else:
        prefix = "<span style='color:#7c3aed;font-weight:600'>Calibration scenario</span>"
    st.markdown(
        f"<div style='background:#f8fafc;border-left:3px solid #cbd5e1;"
        f"padding:0.6rem 0.8rem;border-radius:0 6px 6px 0;margin:0.4rem 0 1rem 0;"
        f"font-size:0.85rem;color:#334155;'>{prefix} &nbsp;|&nbsp; {tagline_html}</div>",
        unsafe_allow_html=True,
    )

num = st.session_state.selected_incident
sc = data["scenarios"].get(num, {})
events = sc.get("events", sc.get("scenario", {}).get("events", []))
if not isinstance(events, list):
    events = []
rules = sc.get("rule_results", {})
llm = sc.get("llm_response", {})

# ── Section B: What Happened ─────────────────────────────────────────────────

st.subheader("What Happened")
st.info(get_scenario_description(data, num))

narrative = llm.get("narrative", "")
if narrative:
    st.markdown(f'<div class="narrative-box">{narrative}</div>', unsafe_allow_html=True)

suspect = llm.get("suspect", "")
if suspect:
    st.markdown(f"**Primary suspect:** {suspect}")

# ── Section C: Detection Comparison ──────────────────────────────────────────

st.subheader("Detection Comparison")
st.caption("How the rule engine and LLM each assessed this incident.")

col_rule, col_llm = st.columns(2)

# --- Rule Engine ---
with col_rule:
    st.markdown("**Rule Engine**")
    rule_verdict = rules.get("verdict", "unknown")
    _rv_colors = {"attack": "#ef4444", "suspicious": "#f59e0b", "clear": "#22c55e"}
    rv_color = _rv_colors.get(rule_verdict, "#6b7280")
    rv_display = rule_verdict.upper()
    st.markdown(
        f'<span style="color:{rv_color};font-weight:700;font-family:JetBrains Mono,monospace;font-size:0.85rem;">{rv_display}</span>',
        unsafe_allow_html=True,
    )
    alert_count = rules.get("alert_count", 0)
    st.markdown(f"Alerts triggered: **{alert_count}**")

    alerts = rules.get("alerts", [])
    if alerts:
        html_parts = []
        for a in alerts:
            rname = a.get("rule_name", a.get("rule_id", ""))
            desc = a.get("description", "")
            html_parts.append(
                f'<div class="alert-card">'
                f'<div class="rule-name">{rname}</div>'
                f'<div class="rule-desc">{desc}</div>'
                f'</div>'
            )
        st.markdown("".join(html_parts), unsafe_allow_html=True)
    else:
        st.markdown("No rules triggered.")

# --- LLM Analyst ---
with col_llm:
    st.markdown("**LLM Analyst**")
    llm_verdict = llm.get("verdict", "UNKNOWN")
    confidence = llm.get("confidence", "")
    badge_html = verdict_badge(llm_verdict)
    conf_html = f'<span style="font-family:JetBrains Mono,monospace;font-size:0.7rem;color:#475569;margin-left:6px;">({confidence})</span>' if confidence else ""
    st.markdown(f"{badge_html}{conf_html}", unsafe_allow_html=True)

    # Evidence for
    ev_for = llm.get("evidence_for", [])
    if ev_for:
        tags = "".join(f'<span class="ev-tag ev-for">{eid}</span>' for eid in ev_for)
        st.markdown(f"Evidence for: {tags}", unsafe_allow_html=True)

    # Evidence against
    ev_against = llm.get("evidence_against", [])
    if ev_against:
        tags = "".join(f'<span class="ev-tag ev-against">{eid}</span>' for eid in ev_against)
        st.markdown(f"Evidence against: {tags}", unsafe_allow_html=True)

    # Gaps
    gaps = llm.get("gaps", [])
    if gaps:
        st.markdown("**Gaps:**")
        for g in gaps:
            st.markdown(f'<div class="gap-item">{g}</div>', unsafe_allow_html=True)

# Verdict disagreement warning
_rule_mapped = {"attack": "YES", "suspicious": "UNKNOWN", "clear": "NO"}.get(rule_verdict, "UNKNOWN")
if _rule_mapped != llm_verdict:
    _llm_label = {"YES": "ATTACK", "NO": "CLEAR"}.get(llm_verdict, llm_verdict)
    st.warning(
        f"The rule engine classified this as **{rule_verdict.upper()}** while the LLM "
        f"classified it as **{_llm_label}**. "
        f"Review the evidence below to understand the disagreement."
    )

# ── Section D: Evidence Timeline ─────────────────────────────────────────────

st.subheader("Evidence Timeline")
st.caption("Chronological view of all logged events. Each bar represents an event, colored by action type.")

if events:
    # Use user as Y-axis if multiple users, otherwise source_type
    users = set(ev.get("user") for ev in events if ev.get("user"))
    use_user_axis = len(users) > 1

    rows = []
    for ev in events:
        ts_raw = ev.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw)
        except (ValueError, TypeError):
            continue
        end = ts + timedelta(minutes=2)
        rows.append({
            "Start": ts,
            "End": end,
            "Category": (ev.get("user", "unknown") or "unknown") if use_user_axis else ev.get("source_type", "unknown"),
            "Action": ev.get("action", "unknown"),
            "event_id": ev.get("event_id", ""),
            "resource": ev.get("resource", "") or "",
            "IP": ev.get("source_ip", "") or "",
            "status": ev.get("status", ""),
            "severity": ev.get("severity", "info"),
        })

    if rows:
        df_tl = pd.DataFrame(rows)
        fig = px.timeline(
            df_tl,
            x_start="Start",
            x_end="End",
            y="Category",
            color="Action",
            hover_data=["event_id", "resource", "IP", "status", "severity"],
        )
        n_categories = len(df_tl["Category"].unique())
        chart_height = max(250, n_categories * 55 + 80)
        fig.update_layout(**plotly_layout(
            height=chart_height,
            showlegend=True,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(size=10)),
        ))
        fig.update_layout(yaxis=dict(autorange="reversed"))
        fig.update_traces(marker_line_width=0)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No parseable timestamps in events.")
else:
    st.info("No events available for this scenario.")

# ── Section E: Event Log ─────────────────────────────────────────────────────

st.subheader("Event Log")
st.caption("Raw log entries. Filter by source type to focus on specific servers.")

if events:
    all_sources = sorted({ev.get("source_type", "unknown") for ev in events})
    selected_sources = st.multiselect("Source type filter", all_sources, default=all_sources)

    filtered = [ev for ev in events if ev.get("source_type", "unknown") in selected_sources]

    if filtered:
        header = "<tr><th>Time</th><th>Source</th><th>User</th><th>Action</th><th>Resource</th><th>IP</th><th>Status</th><th>Severity</th></tr>"
        body_rows = []
        for ev in filtered:
            sev = ev.get("severity", "info")
            row_class = ""
            if sev in ("critical", "high"):
                row_class = ' class="row-critical"'
            elif sev in ("medium", "warning"):
                row_class = ' class="row-warning"'
            elif sev in ("clear", "info", "low"):
                row_class = ' class="row-clear"'

            ts_raw = ev.get("timestamp", "")
            try:
                ts_display = datetime.fromisoformat(ts_raw).strftime("%Y-%m-%d %H:%M")
            except (ValueError, TypeError):
                ts_display = ts_raw

            sev_color = SEV_COLORS.get(sev, "#6b7280")
            sev_html = f'<span style="color:{sev_color};font-weight:600;">{sev}</span>'

            body_rows.append(
                f"<tr{row_class}>"
                f"<td>{ts_display}</td>"
                f"<td>{ev.get('source_type', '')}</td>"
                f"<td>{ev.get('user', '')}</td>"
                f"<td>{ev.get('action', '')}</td>"
                f"<td>{ev.get('resource', '') or ''}</td>"
                f"<td>{ev.get('source_ip', '') or ''}</td>"
                f"<td>{ev.get('status', '')}</td>"
                f"<td>{sev_html}</td>"
                f"</tr>"
            )
        table_html = f'<table class="q-table">{header}{"".join(body_rows)}</table>'
        st.markdown(table_html, unsafe_allow_html=True)
    else:
        st.info("No events match the selected source types.")
else:
    st.info("No events available for this scenario.")

# ── Section F: Attack Chain ──────────────────────────────────────────────────

attack_chain = llm.get("attack_chain", [])
if attack_chain:
    st.subheader("Attack Chain")
    st.caption("Step-by-step attack reconstruction as identified by the LLM analyst.")

    chain_html = []
    for step in attack_chain:
        step_num = step.get("step", "?")
        evt_id = step.get("event_id", "")
        desc = step.get("description", "")
        chain_html.append(
            f'<div class="chain-step">'
            f'<span class="chain-num">{step_num}</span>'
            f'<span class="chain-evt">{evt_id}</span>'
            f'<span class="chain-desc">{desc}</span>'
            f'</div>'
        )
    st.markdown("".join(chain_html), unsafe_allow_html=True)

# ── Section G: Evidence Quality ──────────────────────────────────────────────

st.subheader("Evidence Quality")
st.caption("How trustworthy is the LLM's analysis? Checks for fabricated references and unsupported claims.")

ev_rec = _eval_for_scenario(data, num)
if ev_rec:
    hall = ev_rec.get("hallucination_report", {})
    evt_refs = hall.get("event_references", {})
    valid_refs = evt_refs.get("valid_references", 0)
    total_refs = evt_refs.get("total_references", 0)
    hallucinated = evt_refs.get("hallucinated_events", 0)
    grounding_pct = ev_rec.get("llm_quality", {}).get("evidence_grounding_pct", 0) or 0
    # Citation validity = fraction of cited event_ids that resolved to real
    # events. More meaningful than evidence_grounding_pct on BENIGN scenarios
    # (which have no attack-chain steps to score).
    citation_validity = (valid_refs / total_refs * 100) if total_refs else None
    timeline_ok = hall.get("timeline_correctness", {}).get("chronologically_correct", True)

    c1, c2, c3, c4 = st.columns(4)
    c1.metric(
        "Valid References",
        f"{valid_refs} / {total_refs}",
        help="Event IDs cited by the LLM that actually exist in the log data. The seven-check validator flags any citation that doesn't resolve to an event in the input timeline.",
    )
    c2.metric(
        "Hallucinated Events",
        str(hallucinated),
        help="Event IDs the LLM referenced that don't exist in the input — fabricated evidence. Across all 115 scenarios this is 0.",
    )
    c3.metric(
        "Citation Validity",
        f"{citation_validity:.1f}%" if citation_validity is not None else "n/a",
        delta="OK" if citation_validity == 100 else None,
        help="Fraction of LLM event-id references that resolve to real events in the input timeline. The corpus-wide figure is 99.95%.",
    )
    c4.metric(
        "Timeline Order",
        "OK" if timeline_ok else "VIOLATION",
        delta=None if timeline_ok else "out-of-order step",
        help="The attack-chain step timestamps are non-decreasing when matched against their cited events. 1 violation across 115 scenarios.",
    )
    if grounding_pct > 0:
        st.caption(
            f"Attack-chain grounding (steps with explicit event-id citations): {grounding_pct:.1f}%. "
            "Benign scenarios usually have no attack chain to grade, so this metric reads 0% even when every cited event is valid."
        )
else:
    st.info("No evaluation data available for this scenario.")
