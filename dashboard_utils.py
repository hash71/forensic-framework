"""Shared utilities for the Forensic Operations Center dashboard."""
import json
import streamlit as st
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

INCIDENT_NAMES = {
    1: "Normal Baseline", 2: "Noisy Benign", 3: "Obvious Attack",
    4: "Subtle Insider Threat", 5: "Session Hijack",
    6: "After-Hours Maintenance", 7: "Failed Credential Stuffing",
    8: "Full Infrastructure Attack", 9: "Incomplete Logs",
    10: "Delayed Events", 11: "Benign Then Compromised",
    12: "Conflicting Signals", 13: "Ultra-Slow Exfiltration",
    14: "False Flag / Misdirection", 15: "End-of-Quarter Bulk",
}

SOURCE_TYPE_INFO = {
    "auth": {"icon": "\U0001f510", "server": "Authentication Server", "color": "#0891b2"},
    "file_access": {"icon": "\U0001f4c1", "server": "File Server", "color": "#059669"},
    "admin": {"icon": "\u2699\ufe0f", "server": "Admin Console", "color": "#7c3aed"},
    "network": {"icon": "\U0001f310", "server": "Network Devices", "color": "#d97706"},
    "database": {"icon": "\U0001f5c4\ufe0f", "server": "Database Server", "color": "#dc2626"},
    "web_server": {"icon": "\U0001f30d", "server": "Web Server", "color": "#2563eb"},
    "email": {"icon": "\U0001f4e7", "server": "Mail Server", "color": "#ea580c"},
}

SEV_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "warning": "#f59e0b",
    "low": "#3b82f6",
    "info": "#6b7280",
    "clear": "#22c55e",
}

RULE_DESCRIPTIONS = {
    "R001": ("unusual_login_ip", "Flags logins from IP addresses not in the user's baseline"),
    "R002": ("off_hours_access", "Flags activity outside normal business hours (09:00-17:00)"),
    "R003": ("privilege_escalation", "Flags when a user elevates their own access privileges"),
    "R004": ("bulk_download", "Flags download of more than N files in a short window"),
    "R005": ("cross_department_access", "Flags access to directories outside the user's department"),
    "R006": ("log_deletion", "Flags deletion of log files (anti-forensics indicator)"),
    "R007": ("failed_login_spike", "Flags multiple failed login attempts within a short window"),
    "R008": ("privilege_then_download", "Compound rule: escalation followed by bulk download"),
    "R012": ("lateral_movement", "Flags session activity spanning multiple hosts"),
}

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

@st.cache_data
def load_all_data():
    data = {"scenarios": {}}
    scenarios_dir = PROJECT_ROOT / "data" / "scenarios"
    normalized_dir = PROJECT_ROOT / "data" / "normalized"
    llm_dir = PROJECT_ROOT / "data" / "llm_responses"

    scenario_files = sorted(scenarios_dir.glob("scenario_*.json"))
    scenario_nums = sorted(int(f.stem.replace("scenario_", "")) for f in scenario_files)

    for num in scenario_nums:
        entry = {}
        sf = scenarios_dir / f"scenario_{num}.json"
        if sf.exists():
            with open(sf) as f:
                entry["scenario"] = json.load(f)
        for artefact in ("events", "timeline", "rule_results", "correlations"):
            af = normalized_dir / f"scenario_{num}_{artefact}.json"
            if af.exists():
                with open(af) as f:
                    entry[artefact] = json.load(f)
        lf = llm_dir / f"scenario_{num}_response.json"
        if lf.exists():
            with open(lf) as f:
                entry["llm_response"] = json.load(f)
        data["scenarios"][num] = entry

    eval_path = PROJECT_ROOT / "data" / "evaluation_results.json"
    if eval_path.exists():
        with open(eval_path) as f:
            data["evaluation_results"] = json.load(f)

    gt_path = PROJECT_ROOT / "data" / "ground_truth" / "ground_truth.json"
    if gt_path.exists():
        with open(gt_path) as f:
            data["ground_truth"] = json.load(f)

    ub_path = PROJECT_ROOT / "data" / "user_baselines.json"
    if ub_path.exists():
        with open(ub_path) as f:
            data["user_baselines"] = json.load(f)

    stress_path = PROJECT_ROOT / "data" / "stress_tests" / "stress_test_results.json"
    if stress_path.exists():
        with open(stress_path) as f:
            data["stress_tests"] = json.load(f)

    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _eval_for_scenario(data, num):
    for rec in data.get("evaluation_results", []):
        if rec.get("scenario") == num:
            return rec
    return None


def get_incident_list(data):
    incidents = []
    for num in sorted(data["scenarios"].keys()):
        sc = data["scenarios"][num]
        ev = _eval_for_scenario(data, num)
        label = ev["ground_truth_label"] if ev else sc.get("scenario", {}).get("label", "UNKNOWN")
        llm_resp = sc.get("llm_response", {})
        verdict = llm_resp.get("verdict", "UNKNOWN")
        alert_count = sc.get("rule_results", {}).get("alert_count", 0)
        if verdict == "YES":
            severity = "critical"
        elif ev and ev.get("rule_verdict") == "suspicious":
            severity = "warning"
        else:
            severity = "clear"
        incidents.append({
            "num": num,
            "name": INCIDENT_NAMES.get(num, f"Scenario {num}"),
            "label": label,
            "verdict": verdict,
            "alert_count": alert_count,
            "severity": severity,
        })
    return incidents


def verdict_badge(verdict, tooltip=None):
    badge_style = "padding:2px 8px;border-radius:3px;font-size:0.65rem;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:0.05em;"
    if verdict == "YES":
        tt = tooltip or "LLM classified this incident as a confirmed attack"
        return f'<span class="tt tt-clean" data-tip="{tt}" style="background:#ef4444;color:#fff;{badge_style}">ATTACK</span>'
    elif verdict == "NO":
        tt = tooltip or "LLM classified this incident as benign activity"
        return f'<span class="tt tt-clean" data-tip="{tt}" style="background:#22c55e;color:#fff;{badge_style}">CLEAR</span>'
    tt = tooltip or "LLM could not determine a definitive classification"
    return f'<span class="tt tt-clean" data-tip="{tt}" style="background:#f59e0b;color:#fff;{badge_style}">UNKNOWN</span>'


def severity_dot(severity):
    color = SEV_COLORS.get(severity, "#6b7280")
    labels = {"critical": "Critical — LLM confirmed attack", "warning": "Warning — suspicious activity detected", "clear": "Clear — no threat detected"}
    tt = labels.get(severity, severity)
    return f'<span class="tt tt-clean" data-tip="{tt}" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:{color};border-bottom:none;"></span>'


def plotly_layout(**overrides):
    base = dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#f8fafc",
        font=dict(family="JetBrains Mono, monospace", color="#475569", size=11),
        margin=dict(l=40, r=20, t=36, b=36),
        xaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
        yaxis=dict(gridcolor="#e2e8f0", zerolinecolor="#e2e8f0"),
    )
    base.update(overrides)
    return base


def get_scenario_description(data, num):
    sc = data["scenarios"].get(num, {})
    return sc.get("scenario", {}).get("description", "No description available.")


def get_ground_truth_info(data, num):
    gt = data.get("ground_truth", {})
    for s in gt.get("scenarios", []):
        if s.get("id") == f"scenario_{num}":
            return s
    return {}


# ---------------------------------------------------------------------------
# Tooltip helper
# ---------------------------------------------------------------------------

def tip(content, tooltip, **style_kw):
    """Wrap content in a tooltip span. style_kw become inline CSS properties."""
    safe_tip = tooltip.replace('"', '&quot;').replace("'", "&#39;").replace("\n", "&#10;")
    style = ";".join(f"{k.replace('_','-')}:{v}" for k, v in style_kw.items()) if style_kw else ""
    style_attr = f' style="{style}"' if style else ""
    return f'<span class="tt" data-tip="{safe_tip}"{style_attr}>{content}</span>'


# ---------------------------------------------------------------------------
# CSS -- Light operational theme
# ---------------------------------------------------------------------------

THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@400;500;600;700&display=swap');

:root {
--bg: #f8fafc;
--surface: #ffffff;
--elevated: #f1f5f9;
--border: #e2e8f0;
--text-primary: #0f172a;
--text-secondary: #475569;
--text-muted: #94a3b8;
--accent: #2563eb;
--success: #16a34a;
--danger: #dc2626;
--warning: #d97706;
}

html, body, .stApp {
background: var(--bg) !important;
color: var(--text-primary) !important;
font-family: 'Outfit', sans-serif !important;
}

section[data-testid="stSidebar"] {
background: var(--surface) !important;
border-right: 1px solid var(--border) !important;
}

section[data-testid="stSidebar"] * {
color: var(--text-secondary) !important;
}

.block-container {
max-width: 1600px !important;
padding-top: 0.5rem !important;
padding-bottom: 0 !important;
}

#MainMenu, footer, [data-testid="stToolbar"], .stDeployButton,
header[data-testid="stHeader"] {
display: none !important;
}

h1, h2, h3, h4, h5, h6 {
font-family: 'Outfit', sans-serif !important;
color: var(--text-primary) !important;
}

p, span, div, td, th, li, label {
color: var(--text-primary) !important;
}

.stSelectbox label, .stMultiSelect label, .stRadio label {
color: var(--text-secondary) !important;
font-family: 'JetBrains Mono', monospace !important;
font-size: 0.7rem !important;
text-transform: uppercase !important;
letter-spacing: 0.05em !important;
}

div[data-baseweb="select"] {
background: var(--surface) !important;
border-color: var(--border) !important;
}

div[data-baseweb="select"] * {
color: var(--text-primary) !important;
background: var(--surface) !important;
}

div[data-baseweb="popover"] {
background: var(--surface) !important;
border: 1px solid var(--border) !important;
}

div[data-baseweb="popover"] li {
color: var(--text-primary) !important;
background: var(--surface) !important;
}

div[data-baseweb="popover"] li:hover {
background: var(--elevated) !important;
}

.stTabs [data-baseweb="tab-list"] {
background: transparent !important;
border-bottom: 1px solid var(--border) !important;
gap: 0 !important;
}

.stTabs [data-baseweb="tab"] {
color: var(--text-muted) !important;
font-family: 'JetBrains Mono', monospace !important;
font-size: 0.75rem !important;
background: transparent !important;
border: none !important;
padding: 0.5rem 1rem !important;
}

.stTabs [aria-selected="true"] {
color: var(--accent) !important;
border-bottom: 2px solid var(--accent) !important;
}

/* --- Tooltips --- */
.tt {
position: relative;
cursor: default;
border-bottom: 1px dotted #94a3b8;
}

.tt[data-tip]:hover::after {
content: attr(data-tip);
position: absolute;
bottom: calc(100% + 6px);
left: 50%;
transform: translateX(-50%);
background: #1e293b;
color: #f1f5f9;
font-family: 'JetBrains Mono', monospace;
font-size: 0.62rem;
line-height: 1.45;
padding: 6px 10px;
border-radius: 5px;
white-space: pre-line;
max-width: 320px;
min-width: 120px;
z-index: 9999;
pointer-events: none;
box-shadow: 0 4px 12px rgba(0,0,0,0.15);
letter-spacing: 0.01em;
}

.tt[data-tip]:hover::before {
content: '';
position: absolute;
bottom: calc(100% + 2px);
left: 50%;
transform: translateX(-50%);
border: 4px solid transparent;
border-top-color: #1e293b;
z-index: 9999;
pointer-events: none;
}

/* Tooltip anchored below for header elements */
.tt-below[data-tip]:hover::after {
bottom: auto;
top: calc(100% + 6px);
}

.tt-below[data-tip]:hover::before {
bottom: auto;
top: calc(100% + 2px);
border-top-color: transparent;
border-bottom-color: #1e293b;
}

/* No underline variant */
.tt-clean {
border-bottom: none !important;
}

/* Sidebar nav styling */
section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] span {
font-weight: 600 !important;
text-transform: capitalize !important;
font-size: 0.85rem !important;
}

.stMarkdown p { margin-bottom: 0 !important; }

.stPlotlyChart {
background: transparent !important;
}

@keyframes pulse-live {
0%, 100% { opacity: 1; }
50% { opacity: 0.3; }
}

.live-dot {
display: inline-block;
width: 7px;
height: 7px;
background: #16a34a;
border-radius: 50%;
margin-right: 6px;
animation: pulse-live 2s ease-in-out infinite;
}

.top-bar {
display: flex;
align-items: center;
justify-content: space-between;
padding: 0.6rem 0;
border-bottom: 1px solid #e2e8f0;
margin-bottom: 0.8rem;
}

.top-bar-title {
font-family: 'JetBrains Mono', monospace;
font-size: 0.85rem;
font-weight: 700;
color: #0f172a;
letter-spacing: 0.12em;
text-transform: uppercase;
}

.top-bar-meta {
font-family: 'JetBrains Mono', monospace;
font-size: 0.65rem;
color: #94a3b8;
display: flex;
align-items: center;
gap: 8px;
}

.section-label {
font-family: 'JetBrains Mono', monospace;
font-size: 0.62rem;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.1em;
color: #94a3b8;
margin: 1rem 0 0.5rem 0;
padding-bottom: 0.3rem;
border-bottom: 1px solid #e2e8f0;
}

.panel {
background: #ffffff;
border: 1px solid #e2e8f0;
border-radius: 6px;
padding: 0.8rem;
margin-bottom: 0.6rem;
}

.panel-header {
font-family: 'JetBrains Mono', monospace;
font-size: 0.65rem;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.08em;
color: #94a3b8;
margin-bottom: 0.5rem;
}

.metric-row {
display: flex;
gap: 0.6rem;
margin-bottom: 0.6rem;
}

.metric-box {
background: #ffffff;
border: 1px solid #e2e8f0;
border-radius: 6px;
padding: 0.7rem 1rem;
flex: 1;
text-align: center;
}

.metric-box .label {
font-family: 'JetBrains Mono', monospace;
font-size: 0.55rem;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.08em;
color: #94a3b8;
margin-bottom: 0.25rem;
}

.metric-box .value {
font-family: 'JetBrains Mono', monospace;
font-size: 1.6rem;
font-weight: 700;
line-height: 1.1;
}

.metric-box .sub {
font-family: 'JetBrains Mono', monospace;
font-size: 0.6rem;
color: #94a3b8;
margin-top: 0.15rem;
}

.q-table {
width: 100%;
border-collapse: collapse;
font-family: 'JetBrains Mono', monospace;
font-size: 0.72rem;
}

.q-table th {
text-align: left;
padding: 0.45rem 0.6rem;
font-size: 0.58rem;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.06em;
color: #94a3b8;
border-bottom: 1px solid #e2e8f0;
background: #f8fafc;
}

.q-table td {
padding: 0.5rem 0.6rem;
border-bottom: 1px solid #f1f5f9;
color: #475569;
vertical-align: middle;
}

.q-table tr:hover td {
background: #f0f9ff;
}

.q-table tr.row-critical {
border-left: 3px solid #dc2626;
}

.q-table tr.row-warning {
border-left: 3px solid #d97706;
}

.q-table tr.row-clear {
border-left: 3px solid #16a34a;
}

.cmp-table {
width: 100%;
border-collapse: collapse;
font-family: 'JetBrains Mono', monospace;
font-size: 0.7rem;
}

.cmp-table th {
background: #f8fafc;
color: #94a3b8;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.04em;
font-size: 0.58rem;
padding: 0.5rem;
border-bottom: 1px solid #e2e8f0;
text-align: left;
}

.cmp-table td {
padding: 0.45rem 0.5rem;
border-bottom: 1px solid #f1f5f9;
color: #475569;
}

.cmp-table tr:hover td {
background: #f0f9ff;
}

.narrative-box {
background: #f0f9ff;
border-left: 3px solid #2563eb;
padding: 0.8rem 1rem;
color: #334155;
font-size: 0.8rem;
line-height: 1.6;
border-radius: 0 4px 4px 0;
margin: 0.4rem 0;
font-family: 'Outfit', sans-serif;
}

.chain-step {
display: flex;
gap: 0.6rem;
padding: 0.4rem 0;
border-bottom: 1px solid #f1f5f9;
font-size: 0.72rem;
}

.chain-num {
font-family: 'JetBrains Mono', monospace;
font-weight: 700;
color: #dc2626;
min-width: 20px;
}

.chain-evt {
font-family: 'JetBrains Mono', monospace;
color: #2563eb;
font-size: 0.65rem;
min-width: 80px;
}

.chain-desc {
color: #475569;
}

.ev-tag {
display: inline-block;
font-family: 'JetBrains Mono', monospace;
font-size: 0.6rem;
font-weight: 500;
padding: 0.1rem 0.4rem;
border-radius: 3px;
margin: 0.1rem;
}

.ev-for {
background: #f0fdf4;
color: #166534;
border: 1px solid #bbf7d0;
}

.ev-against {
background: #fffbeb;
color: #92400e;
border: 1px solid #fde68a;
}

.gap-item {
background: #fffbeb;
border-left: 2px solid #d97706;
padding: 0.4rem 0.8rem;
color: #92400e;
font-size: 0.75rem;
margin-bottom: 0.3rem;
border-radius: 0 3px 3px 0;
}

.alert-card {
background: #fff7ed;
border-left: 2px solid #ea580c;
padding: 0.4rem 0.8rem;
margin-bottom: 0.3rem;
border-radius: 0 3px 3px 0;
}

.alert-card .rule-name {
font-family: 'JetBrains Mono', monospace;
font-size: 0.65rem;
color: #ea580c;
font-weight: 600;
}

.alert-card .rule-desc {
font-size: 0.7rem;
color: #475569;
}

.server-card {
background: #ffffff;
border: 1px solid #e2e8f0;
border-radius: 6px;
padding: 0.6rem 0.8rem;
display: flex;
align-items: center;
gap: 0.5rem;
}

.server-card:hover { border-color: #2563eb; }
.server-icon { font-size: 1.2rem; }
.server-name { font-size: 0.7rem; font-weight: 600; color: #0f172a; font-family: 'Outfit', sans-serif; }
.server-count { font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: #94a3b8; }
.server-status { margin-left: auto; width: 6px; height: 6px; border-radius: 50%; background: #16a34a; }

.source-bar {
display: flex;
align-items: center;
gap: 0.4rem;
margin-bottom: 0.25rem;
font-family: 'JetBrains Mono', monospace;
font-size: 0.6rem;
}

.source-bar .bar-label {
width: 70px;
color: #94a3b8;
text-align: right;
overflow: hidden;
text-overflow: ellipsis;
white-space: nowrap;
}

.source-bar .bar-fill {
height: 12px;
border-radius: 2px;
min-width: 2px;
}

.source-bar .bar-count {
color: #475569;
min-width: 30px;
}

.pipeline-flow {
display: flex;
align-items: center;
gap: 0;
justify-content: center;
margin: 1rem 0;
flex-wrap: wrap;
}

.pipeline-step {
background: #ffffff;
border: 1px solid #e2e8f0;
border-radius: 8px;
padding: 0.8rem 1.2rem;
text-align: center;
min-width: 120px;
}

.pipeline-step-title {
font-family: 'JetBrains Mono', monospace;
font-size: 0.65rem;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.06em;
color: #475569;
}

.pipeline-step-value {
font-family: 'Outfit', sans-serif;
font-size: 0.85rem;
font-weight: 600;
color: #0f172a;
margin-top: 0.2rem;
}

.pipeline-arrow {
font-size: 1.2rem;
color: #94a3b8;
padding: 0 0.3rem;
}
</style>
"""


# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------

def apply_theme():
    st.set_page_config(
        page_title="Forensic Operations Center",
        page_icon="\U0001f6e1\ufe0f",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    if "selected_incident" not in st.session_state:
        st.session_state.selected_incident = 1
    st.markdown(THEME_CSS, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------

def render_page_header(title, subtitle):
    st.title(title)
    st.caption(subtitle)


# ---------------------------------------------------------------------------
# Sidebar -- branded info with stats, no navigation
# ---------------------------------------------------------------------------

def render_sidebar_info(data):
    with st.sidebar:
        st.markdown("**Forensic Framework**")
        st.caption("Post-Incident Analysis System")
        st.divider()
        n_scenarios = len(data.get("scenarios", {}))
        eval_results = data.get("evaluation_results", [])
        llm_correct = sum(1 for r in eval_results if r.get("verdict_accuracy", {}).get("llm_correct"))
        rule_correct = sum(1 for r in eval_results if r.get("verdict_accuracy", {}).get("rule_correct"))
        total = len(eval_results) or 1

        # Count events
        total_events = 0
        for sc in data.get("scenarios", {}).values():
            events = sc.get("events", sc.get("scenario", {}).get("events", []))
            if isinstance(events, list):
                total_events += len(events)

        st.markdown(f"**{len(SOURCE_TYPE_INFO)}** servers monitored")
        st.markdown(f"**{total_events:,}** events analyzed")
        st.markdown(f"**{n_scenarios}** scenarios evaluated")
        st.divider()
        st.markdown(f"LLM: **{llm_correct}/{total}** correct ({llm_correct/total*100:.0f}%)")
        st.markdown(f"Rules: **{rule_correct}/{total}** correct ({rule_correct/total*100:.0f}%)")
