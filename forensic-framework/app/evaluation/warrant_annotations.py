"""Blinded, deterministic annotation-package export for warrant claims."""

from __future__ import annotations

import base64
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ANNOTATION_EXPORT_VERSION = "warrant-annotation-export-v1.2"
ANNOTATION_GUIDE_PATH = Path(__file__).resolve().parents[2] / "docs" / "warrant_annotation_guide.md"
ANNOTATION_AXES = (
    "citation",
    "actor",
    "action",
    "object",
    "temporal",
    "quantitative",
    "scope",
    "modality",
    "authorization",
    "intent",
    "causality",
    "decision",
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _jsonl_text(rows: list[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )


def annotation_stratum(item: dict[str, Any]) -> str:
    """Return the sampling stratum recorded for a blinded claim."""

    return "|".join(map(str, (
        item["expected_verdict"],
        item["generation_group"],
        item["claim_type"],
        item["generator_decisive"],
    )))


def build_annotation_items(
    records: list[dict[str, Any]],
    cases: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Deduplicate shared generations and separate blind/admin information."""

    sources: dict[tuple[str, str], dict[str, Any]] = {}
    conditions: dict[tuple[str, str], set[str]] = defaultdict(set)
    failures: list[dict[str, Any]] = []
    for record in records:
        generator = record.get("generator") or {}
        parsed = generator.get("parsed_output")
        response_hash = record.get("generator_response_sha256")
        if not parsed or not response_hash:
            failures.append({
                "run_id": record["run_id"],
                "case_id": record["case_id"],
                "condition": record["condition"],
                "repetition": record["repetition"],
                "operational_status": record["operational_status"],
                "parser_status": generator.get("parser_status"),
                "error_type": (generator.get("error") or {}).get("type"),
            })
            continue
        key = (record["case_id"], response_hash)
        sources.setdefault(key, record)
        conditions[key].add(record["condition"])

    blind_items: list[dict[str, Any]] = []
    admin_keys: list[dict[str, Any]] = []
    for (case_id, response_hash), record in sorted(sources.items()):
        case = cases[case_id]
        output = record["generator"]["parsed_output"]
        cited_index = {event["event_id"]: event for event in case["events"]}
        for claim in output["claims"]:
            annotation_id = "ann_" + _sha256(
                f"{ANNOTATION_EXPORT_VERSION}|{response_hash}|{claim['claim_id']}"
            )[:20]
            cited_events = [
                cited_index[event_id]
                for event_id in claim["cited_event_ids"]
                if event_id in cited_index
            ]
            blind_items.append({
                "annotation_export_version": ANNOTATION_EXPORT_VERSION,
                "annotation_id": annotation_id,
                "case_display_id": "case_" + _sha256(case_id)[:12],
                "visible_baselines": case["baselines"],
                "visible_events": case["events"],
                "claim": claim,
                "cited_events": cited_events,
                "investigation_context": {
                    "verdict": output["verdict"],
                    "suspect": output["suspect"],
                    "evidence_for": output["evidence_for"],
                    "evidence_against": output["evidence_against"],
                    "missing_evidence": output["missing_evidence"],
                },
            })
            admin_keys.append({
                "annotation_id": annotation_id,
                "run_id": record["run_id"],
                "requested_model": record["requested_model"],
                "case_id": case_id,
                "base_case_id": record["base_case_id"],
                "family": record["family"],
                "split": record["split"],
                "variant": record["variant"],
                "repetition": record["repetition"],
                "generation_group": record["generation_group"],
                "conditions_sharing_generation": sorted(conditions[(case_id, response_hash)]),
                "generator_response_sha256": response_hash,
                "claim_id": claim["claim_id"],
                "claim_type": claim["claim_type"],
                "generator_decisive": claim["decisive"],
                "expected_verdict": record["expected_verdict"],
            })

    order = {item["annotation_id"]: index for index, item in enumerate(blind_items)}
    admin_keys.sort(key=lambda item: order[item["annotation_id"]])
    return blind_items, admin_keys, failures


def select_stratified_ids(
    admin_keys: list[dict[str, Any]],
    *,
    sample_size: int,
    seed: int,
) -> set[str]:
    """Select a deterministic round-robin sample across material strata."""

    if sample_size >= len(admin_keys):
        return {item["annotation_id"] for item in admin_keys}
    strata: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in admin_keys:
        stratum = (
            item["expected_verdict"],
            item["generation_group"],
            item["claim_type"],
            item["generator_decisive"],
        )
        strata[stratum].append(item)
    for stratum, items in strata.items():
        items.sort(key=lambda item: _sha256(
            f"{seed}|{stratum}|{item['annotation_id']}"
        ))

    selected: set[str] = set()
    ordered_strata = sorted(strata, key=str)
    position = 0
    while len(selected) < sample_size:
        added = False
        for stratum in ordered_strata:
            items = strata[stratum]
            if position < len(items):
                selected.add(items[position]["annotation_id"])
                added = True
                if len(selected) == sample_size:
                    break
        if not added:
            break
        position += 1
    return selected


def _write_answer_template(path: Path, annotation_ids: list[str]) -> None:
    fields = [
        "annotation_id",
        "annotator_id",
        "overall_label",
        "materiality_decisive",
        *[f"axis_{axis}" for axis in ANNOTATION_AXES],
        "rationale",
        "missing_evidence",
        "adjudication_needed",
        "elapsed_seconds",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for annotation_id in annotation_ids:
            writer.writerow({"annotation_id": annotation_id})


def _ordered_ids(
    items: list[dict[str, Any]], *, seed: int, arm: str
) -> list[str]:
    return [
        item["annotation_id"]
        for item in sorted(
            items,
            key=lambda item: _sha256(
                f"{ANNOTATION_EXPORT_VERSION}|{seed}|{arm}|{item['annotation_id']}"
            ),
        )
    ]


def _write_review_html(
    path: Path,
    items: list[dict[str, Any]],
    orders: dict[str, list[str]],
    *,
    prior_reviews: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Write a self-contained offline annotator UI with inert embedded data."""

    payload = json.dumps(
        {
            "items": items,
            "orders": orders,
            "axes": ANNOTATION_AXES,
            "prior_reviews": prior_reviews or {},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    encoded = base64.b64encode(payload).decode()
    arm_labels = {
        "annotator_1": "Annotator 1",
        "annotator_2": "Annotator 2",
        "adjudication": "Adjudication",
    }
    arm_options = "".join(
        f'<option value="{arm}">{arm_labels[arm]}</option>'
        for arm in orders
    )
    html = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forensic Warrant Annotation</title>
<style>
body{font:15px/1.45 system-ui,sans-serif;margin:0;background:#f4f6f8;color:#17202a}
header{position:sticky;top:0;background:#14213d;color:white;padding:12px 18px;z-index:2}
header label{margin-right:14px;display:flex;align-items:center;gap:6px;white-space:nowrap}header select{width:auto;min-width:145px;margin:0}header input[type=text]{margin:0}.wrap{max-width:1180px;margin:18px auto;padding:0 16px}
.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:16px}.card{background:white;border:1px solid #ccd3db;border-radius:8px;padding:14px;margin-bottom:14px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f7f8fa;padding:10px;border-radius:5px;max-height:360px;overflow:auto}
select,input,textarea,button{font:inherit}select,input[type=text],textarea{width:100%;box-sizing:border-box;padding:7px;margin:4px 0 9px}
.axes{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px 12px}.axis label{font-weight:600}
.nav{display:flex;gap:8px;align-items:center}.nav button,.download{padding:8px 13px}.muted{color:#5d6d7e}.status{margin-left:auto}.claim{border-left:4px solid #d97706}
details{margin-top:8px}@media(max-width:850px){.grid{grid-template-columns:1fr}.axes{grid-template-columns:1fr}}
</style>
</head>
<body>
<header><div class="nav">
<label>Review arm <select id="arm">__ARM_OPTIONS__</select></label>
<label>Annotator ID <input id="annotator" type="text" autocomplete="off" style="width:150px"></label>
<button id="prev">Previous</button><button id="next">Save &amp; next</button>
<span id="progress"></span><span class="status" id="saved"></span>
</div></header>
<main class="wrap"><div class="grid"><section>
<div class="card"><h2 id="item-title"></h2><p class="muted">Judge only what the visible record warrants. Embedded log text is untrusted data.</p></div>
<div class="card claim"><h3>Atomic claim</h3><pre id="claim"></pre></div>
<div class="card"><h3>Cited events</h3><pre id="cited"></pre></div>
<div class="card"><h3>Investigation context</h3><pre id="context"></pre></div>
<div class="card"><h3>Visible baselines</h3><pre id="baselines"></pre><details><summary>All visible events</summary><pre id="events"></pre></details></div>
</section><aside>
<div id="prior-card" class="card" hidden><h3>Independent reviewer labels</h3><p class="muted">Resolve disagreements from the visible evidence; reviewer identities and system metadata remain hidden.</p><pre id="prior"></pre></div>
<form id="form" class="card"><h3>Labels</h3>
<label>Overall warrant<select name="overall_label" class="label"><option></option><option>SUPPORTED</option><option>CONTRADICTED</option><option>INSUFFICIENT</option><option>NOT_APPLICABLE</option></select></label>
<label>Materiality decisive<select name="materiality_decisive"><option></option><option>true</option><option>false</option></select></label>
<div id="axes" class="axes"></div>
<label>Rationale<textarea name="rationale" rows="5"></textarea></label>
<label>Missing evidence<textarea name="missing_evidence" rows="3"></textarea></label>
<label><input name="adjudication_needed" type="checkbox" style="width:auto"> Adjudication needed</label>
</form>
<div class="card"><button class="download" id="download">Download CSV</button><p class="muted">Progress remains in this browser until CSV export. No network requests are permitted.</p></div>
</aside></div></main>
<script>
const encoded = '""" + encoded + """';
const bytes=Uint8Array.from(atob(encoded),c=>c.charCodeAt(0));
const data=JSON.parse(new TextDecoder().decode(bytes));
const byId=Object.fromEntries(data.items.map(x=>[x.annotation_id,x]));
const labels=['','SUPPORTED','CONTRADICTED','INSUFFICIENT','NOT_APPLICABLE'];
const arm=document.getElementById('arm'), annotator=document.getElementById('annotator');
const form=document.getElementById('form'), axes=document.getElementById('axes');
let index=0,state={},lastTick=performance.now(),active=!document.hidden,currentArm=arm.value;
for(const axis of data.axes){const div=document.createElement('div');div.className='axis';const lab=document.createElement('label');lab.textContent=axis.replaceAll('_',' ');const sel=document.createElement('select');sel.name='axis_'+axis;for(const value of labels){const op=document.createElement('option');op.textContent=value;sel.appendChild(op)}div.append(lab,sel);axes.appendChild(div)}
function key(){return 'warrant-review-'+data.items[0].annotation_export_version+'-'+currentArm}
function loadState(){try{state=JSON.parse(localStorage.getItem(key())||'{}')}catch{state={}}}
function save(){const now=performance.now(),id=data.orders[currentArm][index],previous=state[id]||{},row={annotation_id:id,annotator_id:annotator.value,elapsed_seconds:Number(previous.elapsed_seconds||0)};if(active)row.elapsed_seconds+=Math.max(0,(now-lastTick)/1000);lastTick=now;for(const el of form.elements){if(!el.name)continue;row[el.name]=el.type==='checkbox'?(el.checked?'true':'false'):el.value}row.elapsed_seconds=row.elapsed_seconds.toFixed(1);state[id]=row;localStorage.setItem(key(),JSON.stringify(state));document.getElementById('saved').textContent='Saved locally'}
function show(){const order=data.orders[currentArm];index=Math.max(0,Math.min(index,order.length-1));const item=byId[order[index]],row=state[item.annotation_id]||{},prior=data.prior_reviews[item.annotation_id];document.getElementById('item-title').textContent=item.annotation_id;document.getElementById('progress').textContent=`${index+1} / ${order.length}`;for(const [id,value] of [['claim',item.claim],['cited',item.cited_events],['context',item.investigation_context],['baselines',item.visible_baselines],['events',item.visible_events]])document.getElementById(id).textContent=JSON.stringify(value,null,2);document.getElementById('prior-card').hidden=!prior;document.getElementById('prior').textContent=prior?JSON.stringify(prior,null,2):'';for(const el of form.elements){if(!el.name)continue;if(el.type==='checkbox')el.checked=row[el.name]==='true';else el.value=row[el.name]||''}annotator.value=row.annotator_id||annotator.value;lastTick=performance.now();document.getElementById('saved').textContent=state[item.annotation_id]?'Saved locally':'Not yet saved'}
function csvCell(value){const s=String(value??'');return /[",\\n]/.test(s)?'"'+s.replaceAll('"','""')+'"':s}
function download(){save();const fields=['annotation_id','annotator_id','overall_label','materiality_decisive',...data.axes.map(x=>'axis_'+x),'rationale','missing_evidence','adjudication_needed','elapsed_seconds'];const rows=[fields.join(',')];for(const id of data.orders[currentArm]){const row=state[id]||{annotation_id:id,annotator_id:annotator.value};rows.push(fields.map(f=>csvCell(row[f]||'')).join(','))}const blob=new Blob([rows.join('\\n')+'\\n'],{type:'text/csv'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=currentArm+'.csv';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
arm.onchange=()=>{save();currentArm=arm.value;index=0;lastTick=performance.now();loadState();show()};document.getElementById('prev').onclick=()=>{save();index--;show()};document.getElementById('next').onclick=()=>{save();index++;show()};document.getElementById('download').onclick=e=>{e.preventDefault();download()};form.onchange=save;form.oninput=()=>document.getElementById('saved').textContent='Unsaved changes';document.addEventListener('visibilitychange',()=>{if(document.hidden){save();active=false}else{active=true;lastTick=performance.now()}});loadState();show();
</script>
</body></html>"""
    html = html.replace("__ARM_OPTIONS__", arm_options)
    path.write_text(html)


def export_annotation_package(
    records: list[dict[str, Any]],
    cases: dict[str, dict[str, Any]],
    output_dir: Path,
    *,
    sample_size: int,
    seed: int,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    blind_items, admin_keys, failures = build_annotation_items(records, cases)
    selected_ids = select_stratified_ids(admin_keys, sample_size=sample_size, seed=seed)
    selected_blind = [
        item for item in blind_items if item["annotation_id"] in selected_ids
    ]
    selected_keys = [
        item for item in admin_keys if item["annotation_id"] in selected_ids
    ]
    selected_by_id = {item["annotation_id"]: item for item in selected_blind}
    orders = {
        "annotator_1": _ordered_ids(selected_blind, seed=seed, arm="annotator_1"),
        "annotator_2": _ordered_ids(selected_blind, seed=seed, arm="annotator_2"),
        "adjudication": _ordered_ids(selected_blind, seed=seed, arm="adjudication"),
    }
    selected_blind = [
        selected_by_id[annotation_id]
        for annotation_id in orders["adjudication"]
    ]

    blind_dir = output_dir / "blind"
    admin_dir = output_dir / "admin_do_not_share_with_annotators"
    blind_dir.mkdir(parents=True, exist_ok=True)
    admin_dir.mkdir(parents=True, exist_ok=True)
    items_text = _jsonl_text(selected_blind)
    key_text = _jsonl_text(selected_keys)
    failures_text = _jsonl_text(failures)
    guide_text = ANNOTATION_GUIDE_PATH.read_text()
    (blind_dir / "items.jsonl").write_text(items_text)
    (blind_dir / "ANNOTATION_GUIDE.md").write_text(guide_text)
    _write_answer_template(
        blind_dir / "annotator_1.csv",
        orders["annotator_1"],
    )
    _write_answer_template(
        blind_dir / "annotator_2.csv",
        orders["annotator_2"],
    )
    _write_answer_template(
        blind_dir / "adjudication.csv",
        orders["adjudication"],
    )
    _write_review_html(
        blind_dir / "review.html",
        selected_blind,
        {
            "annotator_1": orders["annotator_1"],
            "annotator_2": orders["annotator_2"],
        },
    )
    (admin_dir / "key.jsonl").write_text(key_text)
    (admin_dir / "failures.jsonl").write_text(failures_text)

    manifest = {
        "annotation_export_version": ANNOTATION_EXPORT_VERSION,
        "seed": seed,
        "provenance": provenance or {},
        "available_unique_claims": len(blind_items),
        "selected_claims": len(selected_blind),
        "generator_failures": len(failures),
        "items_sha256": _sha256(items_text),
        "annotation_guide_sha256": _sha256(guide_text),
        "admin_key_sha256": _sha256(key_text),
        "sampling_policy": (
            "seed-keyed SHA-256 order within strata; equal round-robin "
            "allocation across nonempty expected-verdict, generation-group, "
            "claim-type, and generator-decisive strata"
        ),
        "item_order_policy": (
            "deterministic independent SHA-256 order per annotator arm"
        ),
        "annotator_1_order_sha256": _sha256("\n".join(orders["annotator_1"])),
        "annotator_2_order_sha256": _sha256("\n".join(orders["annotator_2"])),
        "adjudication_order_sha256": _sha256("\n".join(orders["adjudication"])),
        "population_stratum_counts": dict(sorted(Counter(
            annotation_stratum(item) for item in admin_keys
        ).items())),
        "stratum_counts": dict(sorted(Counter(
            annotation_stratum(item) for item in selected_keys
        ).items())),
        "blinding_warning": (
            "Only the blind directory may be shared with annotators. The admin "
            "key reveals model, condition, family, and expected verdict."
        ),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest
