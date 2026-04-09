"""Infrastructure — monitoring setup, data pipeline, and detection methods."""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from dashboard_utils import (
    apply_theme, load_all_data, render_page_header, render_sidebar_info,
    tip, SOURCE_TYPE_INFO, RULE_DESCRIPTIONS,
)

# ── Setup ────────────────────────────────────────────────────────────────────
apply_theme()
data = load_all_data()
render_sidebar_info(data)
render_page_header(
    "Infrastructure",
    "What we monitor, how data flows through the pipeline, and the two detection methods compared in this research.",
)

# ── Compute source counts ────────────────────────────────────────────────────
source_counts: dict[str, int] = {}
for sc in data["scenarios"].values():
    for ev in sc.get("events", []):
        stype = ev.get("source_type", "unknown")
        source_counts[stype] = source_counts.get(stype, 0) + 1
total_events = sum(source_counts.values())

# ── Compute LLM quality metrics ──────────────────────────────────────────────
eval_results = data.get("evaluation_results", [])
total_eval = len(eval_results) or 1
rule_correct = sum(1 for r in eval_results if r.get("verdict_accuracy", {}).get("rule_correct"))
llm_correct = sum(1 for r in eval_results if r.get("verdict_accuracy", {}).get("llm_correct"))
avg_hall = sum(r.get("llm_quality", {}).get("hallucination_count", 0) for r in eval_results) / total_eval
grounding_vals = [
    r.get("llm_quality", {}).get("evidence_grounding_pct", 0)
    for r in eval_results
    if r.get("llm_quality", {}).get("evidence_grounding_pct", 0) > 0
]
avg_grounding = sum(grounding_vals) / len(grounding_vals) if grounding_vals else 0
timeline_correct = sum(1 for r in eval_results if r.get("llm_quality", {}).get("timeline_correct", False))
rule_fp = sum(r.get("false_positives", {}).get("rule_fp_count", 0) for r in eval_results)
llm_fp = sum(1 for r in eval_results if r.get("false_positives", {}).get("llm_fp", False))

# ===========================================================================
# Section A: What We Monitor (2 rows: 4 + 3)
# ===========================================================================
st.subheader("What We Monitor")
st.caption("Seven server types generate log events that feed the forensic analysis pipeline.")

src_items = list(SOURCE_TYPE_INFO.items())
max_count = max(source_counts.values()) if source_counts else 1

# Row 1: first 4 servers
row1 = st.columns(4)
for i in range(4):
    src_key, info = src_items[i]
    count = source_counts.get(src_key, 0)
    pct = count / total_events * 100 if total_events else 0
    bar_width = int(count / max_count * 100)
    with row1[i]:
        st.markdown(f"""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;height:100%;">
<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.6rem;">
<span style="font-size:1.8rem;">{info["icon"]}</span>
<div>
<div style="font-weight:600;font-size:0.9rem;color:#0f172a;">{info["server"]}</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#64748b;">{count:,} events ({pct:.0f}%)</div>
</div>
<span style="margin-left:auto;width:8px;height:8px;border-radius:50%;background:#22c55e;flex-shrink:0;"></span>
</div>
<div style="background:#f1f5f9;border-radius:3px;height:6px;overflow:hidden;">
<div style="background:{info['color']};height:100%;width:{bar_width}%;border-radius:3px;"></div>
</div>
</div>""", unsafe_allow_html=True)

# Row 2: last 3 servers
row2 = st.columns([1, 1, 1, 1])
for i in range(3):
    src_key, info = src_items[4 + i]
    count = source_counts.get(src_key, 0)
    pct = count / total_events * 100 if total_events else 0
    bar_width = int(count / max_count * 100)
    with row2[i]:
        st.markdown(f"""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;height:100%;">
<div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:0.6rem;">
<span style="font-size:1.8rem;">{info["icon"]}</span>
<div>
<div style="font-weight:600;font-size:0.9rem;color:#0f172a;">{info["server"]}</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#64748b;">{count:,} events ({pct:.0f}%)</div>
</div>
<span style="margin-left:auto;width:8px;height:8px;border-radius:50%;background:#22c55e;flex-shrink:0;"></span>
</div>
<div style="background:#f1f5f9;border-radius:3px;height:6px;overflow:hidden;">
<div style="background:{info['color']};height:100%;width:{bar_width}%;border-radius:3px;"></div>
</div>
</div>""", unsafe_allow_html=True)

# 4th column: total summary
with row2[3]:
    st.markdown(f"""
<div style="background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;padding:1rem;height:100%;display:flex;flex-direction:column;justify-content:center;text-align:center;">
<div style="font-family:'JetBrains Mono',monospace;font-size:2rem;font-weight:700;color:#0f172a;">{total_events:,}</div>
<div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem;">total events across<br>all 15 scenarios</div>
</div>""", unsafe_allow_html=True)

# ===========================================================================
# Section B: Detection Pipeline
# ===========================================================================
st.markdown("---")
st.subheader("How Detection Works")
st.caption("Log events flow through a multi-stage pipeline. Both methods analyze the same normalized data independently.")

# Pipeline flow
pipeline_html = '<div class="pipeline-flow">'
steps = [
    ("SOURCES", "7 Servers", "#0891b2"),
    ("COLLECTION", f"{total_events:,} Events", "#059669"),
    ("NORMALIZATION", "Standardized", "#7c3aed"),
    ("ANALYSIS", "Rules + LLM", "#2563eb"),
    ("EVALUATION", "15 Scenarios", "#dc2626"),
]
for i, (title, value, color) in enumerate(steps):
    if i > 0:
        pipeline_html += '<div class="pipeline-arrow">→</div>'
    pipeline_html += f'<div class="pipeline-step" style="border-top:3px solid {color};">'
    pipeline_html += f'<div class="pipeline-step-title">{title}</div>'
    pipeline_html += f'<div class="pipeline-step-value">{value}</div>'
    pipeline_html += '</div>'
pipeline_html += '</div>'
st.markdown(pipeline_html, unsafe_allow_html=True)

# ===========================================================================
# Section C: The Two Methods (side by side)
# ===========================================================================
st.markdown("---")
st.subheader("Detection Methods Compared")
st.caption("The same normalized events are analyzed independently by both methods. Here's what each brings to the table.")

col_rules, col_llm = st.columns(2)

# ── Left: Rule Engine ────────────────────────────────────────────────────────
with col_rules:
    st.markdown(f"""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1.2rem;border-top:3px solid #64748b;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.8rem;">
<div style="font-weight:700;font-size:1.1rem;color:#0f172a;">Rule Engine</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#64748b;background:#f1f5f9;padding:2px 8px;border-radius:4px;">Threshold-based</div>
</div>
<div style="display:flex;gap:1rem;margin-bottom:1rem;">
<div style="text-align:center;flex:1;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;color:#64748b;">{rule_correct}/{total_eval}</div>
<div style="font-size:0.65rem;color:#94a3b8;text-transform:uppercase;">Accuracy</div>
</div>
<div style="text-align:center;flex:1;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;color:#d97706;">{rule_fp}</div>
<div style="font-size:0.65rem;color:#94a3b8;text-transform:uppercase;">False Positives</div>
</div>
<div style="text-align:center;flex:1;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;color:#0f172a;">9</div>
<div style="font-size:0.65rem;color:#94a3b8;text-transform:uppercase;">Rules</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

    # Rules table
    rows_html = ""
    for rule_id, (rule_name, description) in sorted(RULE_DESCRIPTIONS.items()):
        rows_html += f'<tr><td style="color:#2563eb;font-weight:600;white-space:nowrap;">{rule_id}</td><td style="font-weight:500;white-space:nowrap;">{rule_name}</td><td style="color:#475569;">{description}</td></tr>'

    st.markdown(
        f'<table class="cmp-table" style="font-size:0.68rem;"><thead><tr><th>ID</th><th>Rule</th><th>What it checks</th></tr></thead><tbody>{rows_html}</tbody></table>',
        unsafe_allow_html=True,
    )

    st.markdown("""
<div style="background:#fffbeb;border-left:3px solid #d97706;padding:0.6rem 0.8rem;border-radius:0 6px 6px 0;margin-top:0.5rem;font-size:0.8rem;color:#92400e;">
<strong>Limitation:</strong> Rules check individual events against fixed thresholds. They cannot reason about intent, correlate events across days, or detect attacks that stay below individual alert thresholds.
</div>""", unsafe_allow_html=True)

# ── Right: LLM Analyst ───────────────────────────────────────────────────────
with col_llm:
    st.markdown(f"""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1.2rem;border-top:3px solid #2563eb;">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.8rem;">
<div style="font-weight:700;font-size:1.1rem;color:#0f172a;">LLM Analyst</div>
<div style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#2563eb;background:#eff6ff;padding:2px 8px;border-radius:4px;">Qwen 3.5-27B</div>
</div>
<div style="display:flex;gap:1rem;margin-bottom:1rem;">
<div style="text-align:center;flex:1;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;color:#2563eb;">{llm_correct}/{total_eval}</div>
<div style="font-size:0.65rem;color:#94a3b8;text-transform:uppercase;">Accuracy</div>
</div>
<div style="text-align:center;flex:1;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;color:#16a34a;">{llm_fp}</div>
<div style="font-size:0.65rem;color:#94a3b8;text-transform:uppercase;">False Positives</div>
</div>
<div style="text-align:center;flex:1;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;font-weight:700;color:#0f172a;">{avg_grounding:.0f}%</div>
<div style="font-size:0.65rem;color:#94a3b8;text-transform:uppercase;">Grounding</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

    # What the LLM produces
    st.markdown("""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:0.8rem;margin-bottom:0.5rem;">
<div style="font-weight:600;font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem;">What the LLM receives</div>
<div style="font-size:0.82rem;color:#475569;">All normalized log events for a scenario — timestamps, users, actions, resources, IP addresses, and severity levels.</div>
</div>
""", unsafe_allow_html=True)

    st.markdown("""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:0.8rem;margin-bottom:0.5rem;">
<div style="font-weight:600;font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem;">What the LLM outputs</div>
<div style="font-size:0.82rem;color:#475569;">
<strong>Verdict</strong> (attack/clear) · <strong>Confidence</strong> (high/medium/low) · <strong>Narrative</strong> (plain-English explanation) · <strong>Suspect</strong> (primary user) · <strong>Attack chain</strong> (step-by-step reconstruction) · <strong>Evidence</strong> (supporting & contradicting event IDs) · <strong>Gaps</strong> (missing information)
</div>
</div>
""", unsafe_allow_html=True)

    # Quality metrics
    st.markdown(f"""
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:0.8rem;">
<div style="font-weight:600;font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.5rem;">Quality checks</div>
<div style="display:flex;gap:0.5rem;">
<div style="flex:1;text-align:center;background:#f8fafc;border-radius:6px;padding:0.4rem;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;color:#d97706;">{avg_hall:.1f}</div>
<div style="font-size:0.6rem;color:#94a3b8;">hallucinations/case</div>
</div>
<div style="flex:1;text-align:center;background:#f8fafc;border-radius:6px;padding:0.4rem;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;color:#16a34a;">{avg_grounding:.0f}%</div>
<div style="font-size:0.6rem;color:#94a3b8;">evidence grounding</div>
</div>
<div style="flex:1;text-align:center;background:#f8fafc;border-radius:6px;padding:0.4rem;">
<div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;font-weight:700;color:#2563eb;">{timeline_correct}/{total_eval}</div>
<div style="font-size:0.6rem;color:#94a3b8;">timeline accuracy</div>
</div>
</div>
</div>""", unsafe_allow_html=True)

    st.markdown("""
<div style="background:#f0fdf4;border-left:3px solid #16a34a;padding:0.6rem 0.8rem;border-radius:0 6px 6px 0;margin-top:0.5rem;font-size:0.8rem;color:#166534;">
<strong>Advantage:</strong> The LLM reasons about context — correlating events across time, understanding user intent, and detecting attacks that stay below individual rule thresholds.
</div>""", unsafe_allow_html=True)
