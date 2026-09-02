"""Deterministic checks for forensic evidential warrant.

These checks are deliberately conservative.  They can establish exact matches
and identify contradictions, but they do not pretend that string overlap proves
intent, causality, authorization, or a final incident decision.  Ambiguous
claims are labeled ``INSUFFICIENT`` and may be sent to an independent verifier
or human reviewer.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from datetime import datetime
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from pydantic import Field

from app.evaluation.claims import (
    AtomicClaim,
    Authorization,
    ClaimType,
    EvidenceRelation,
    InvestigationOutput,
    Modality,
    Quantity,
    StrictModel,
    Verdict,
)

WARRANT_EVALUATOR_VERSION = "warrant-evaluator-v1.1"


class WarrantLabel(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT = "INSUFFICIENT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class WarrantAxis(str, Enum):
    CITATION = "citation"
    ACTOR = "actor"
    ACTION = "action"
    OBJECT = "object"
    TEMPORAL = "temporal"
    QUANTITATIVE = "quantitative"
    SCOPE = "scope"
    MODALITY = "modality"
    AUTHORIZATION = "authorization"
    INTENT = "intent"
    CAUSALITY = "causality"
    DECISION = "decision"
    EVIDENCE_RELATION = "evidence_relation"


class AxisAssessment(StrictModel):
    axis: WarrantAxis
    label: WarrantLabel
    reason: str


class ClaimAssessment(StrictModel):
    claim_id: str
    decisive: bool
    overall_label: WarrantLabel
    valid_cited_event_ids: list[str]
    invalid_cited_event_ids: list[str]
    axes: list[AxisAssessment]

    def axis(self, name: WarrantAxis) -> AxisAssessment:
        for assessment in self.axes:
            if assessment.axis == name:
                return assessment
        raise KeyError(name)


class WarrantReport(StrictModel):
    case_id: str
    total_claims: int
    decisive_claims: int
    supported_claims: int
    contradicted_claims: int
    insufficient_claims: int
    citation_validity: float
    citation_completeness: float
    unwarranted_decisive_claim_rate: float
    assessments: list[ClaimAssessment]


class CounterEvidenceCandidate(StrictModel):
    event_id: str
    reason: str
    decisive: bool = False


class CounterEvidenceReport(StrictModel):
    available: list[CounterEvidenceCandidate]
    cited_event_ids: list[str]
    missed_event_ids: list[str]
    decisive_missed_event_ids: list[str]
    recall: float | None


class ReviewDisposition(str, Enum):
    ALLOW = "ALLOW"
    ABSTAIN = "ABSTAIN"


class ReviewDecision(StrictModel):
    disposition: ReviewDisposition
    original_verdict: Verdict
    reviewed_verdict: Verdict
    reasons: list[str]
    coverage: float = Field(ge=0.0, le=1.0)


_ACTION_GROUPS = (
    {"login", "login_success", "authenticate", "authentication_success", "user_login"},
    {"login_failed", "failed_login", "authentication_failure", "auth_failure"},
    {"file_download", "download", "object_download", "get_object"},
    {"file_read", "read", "object_read", "get_file"},
    {"file_upload", "upload", "object_upload", "put_object"},
    {"privilege_change", "role_change", "permission_change", "policy_change"},
    {"privilege_revert", "role_revert", "permission_revert"},
    {"log_delete", "delete_log", "clear_log", "audit_log_delete"},
    {"network_transfer", "data_transfer", "external_transfer", "egress"},
    {"api_call", "cloud_api_call", "request"},
    {"ticket_approved", "maintenance_approved", "approval"},
    {"logout", "session_end"},
)

_ACTION_EQUIVALENTS: dict[str, set[str]] = {}
for _group in _ACTION_GROUPS:
    for _action in _group:
        _ACTION_EQUIVALENTS[_action] = _group

_INTENT_TERMS = {
    "steal", "stole", "theft", "malicious", "maliciously", "deliberate",
    "deliberately", "intent", "intentionally", "conceal", "hide",
    "cover_tracks", "evade", "exfiltrate", "exfiltration",
}

_CAUSAL_TERMS = {
    "caused", "causes", "causal", "because", "resulted_in", "led_to",
    "therefore", "using", "via",
}


def _canonical(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9/_.:-]+", "_", text)
    return text.strip("_")


def _event_actors(event: dict[str, Any]) -> set[str]:
    actors: set[str] = set()
    for key in ("user", "actor", "principal", "username", "account"):
        if event.get(key):
            actors.add(_canonical(event[key]))
    metadata = event.get("metadata") or {}
    if isinstance(metadata, dict):
        for key in ("user", "actor", "principal", "username", "account", "assumed_by"):
            if metadata.get(key):
                actors.add(_canonical(metadata[key]))
    return actors


def _event_actions(event: dict[str, Any]) -> set[str]:
    actions = {_canonical(event.get("action"))}
    metadata = event.get("metadata") or {}
    if isinstance(metadata, dict):
        for key in ("action", "event_name", "operation"):
            if metadata.get(key):
                actions.add(_canonical(metadata[key]))
    return {action for action in actions if action}


def _event_objects(event: dict[str, Any]) -> set[str]:
    objects: set[str] = set()
    for key in ("resource", "object", "target", "destination", "file_path", "host"):
        if event.get(key):
            objects.add(_canonical(event[key]))
    metadata = event.get("metadata") or {}
    if isinstance(metadata, dict):
        for key in (
            "resource", "object", "target", "destination", "file_path",
            "bucket", "host", "role", "destination_ip",
        ):
            if metadata.get(key):
                objects.add(_canonical(metadata[key]))
    return objects


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _axis(axis: WarrantAxis, label: WarrantLabel, reason: str) -> AxisAssessment:
    return AxisAssessment(axis=axis, label=label, reason=reason)


def _citation_axis(claim: AtomicClaim, event_index: dict[str, dict]) -> AxisAssessment:
    if not claim.cited_event_ids:
        return _axis(WarrantAxis.CITATION, WarrantLabel.INSUFFICIENT, "No event identifier was cited.")
    invalid = [event_id for event_id in claim.cited_event_ids if event_id not in event_index]
    if invalid:
        return _axis(
            WarrantAxis.CITATION,
            WarrantLabel.INSUFFICIENT,
            f"Unknown event identifiers: {', '.join(invalid)}.",
        )
    return _axis(
        WarrantAxis.CITATION,
        WarrantLabel.SUPPORTED,
        "Every cited event identifier resolves to visible evidence.",
    )


def _actor_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    if not claim.subject:
        return _axis(WarrantAxis.ACTOR, WarrantLabel.NOT_APPLICABLE, "The claim names no actor.")
    if not events:
        return _axis(WarrantAxis.ACTOR, WarrantLabel.INSUFFICIENT, "No valid cited events remain.")
    subject = _canonical(claim.subject)
    actors = set().union(*(_event_actors(event) for event in events))
    if subject in actors:
        return _axis(WarrantAxis.ACTOR, WarrantLabel.SUPPORTED, "The named account or actor appears in cited evidence.")
    if actors:
        return _axis(
            WarrantAxis.ACTOR,
            WarrantLabel.CONTRADICTED,
            f"Cited evidence names other actors: {', '.join(sorted(actors))}.",
        )
    return _axis(WarrantAxis.ACTOR, WarrantLabel.INSUFFICIENT, "Cited evidence contains no actor field.")


def _action_matches(predicate: str, observed: str) -> bool:
    predicate = _canonical(predicate)
    observed = _canonical(observed)
    if predicate == observed:
        return True
    return observed in _ACTION_EQUIVALENTS.get(predicate, set())


def _action_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    if claim.claim_type == ClaimType.DECISION:
        return _axis(WarrantAxis.ACTION, WarrantLabel.NOT_APPLICABLE, "Decision language is evaluated on the decision axis.")
    if not events:
        return _axis(WarrantAxis.ACTION, WarrantLabel.INSUFFICIENT, "No valid cited events remain.")
    predicate = _canonical(claim.predicate)
    observed = set().union(*(_event_actions(event) for event in events))
    if any(_action_matches(predicate, action) for action in observed):
        return _axis(WarrantAxis.ACTION, WarrantLabel.SUPPORTED, "The claimed action matches a cited event action.")

    tokens = set(predicate.split("_"))
    if tokens & _INTENT_TERMS or tokens & _CAUSAL_TERMS or predicate.startswith("legacy_"):
        return _axis(
            WarrantAxis.ACTION,
            WarrantLabel.INSUFFICIENT,
            "The predicate is interpretive and is not directly established by an event action.",
        )
    if observed:
        return _axis(
            WarrantAxis.ACTION,
            WarrantLabel.CONTRADICTED,
            f"Claimed action '{predicate}' does not match cited actions: {', '.join(sorted(observed))}.",
        )
    return _axis(WarrantAxis.ACTION, WarrantLabel.INSUFFICIENT, "Cited evidence contains no action field.")


def _object_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    if claim.object is None or claim.claim_type == ClaimType.DECISION:
        return _axis(WarrantAxis.OBJECT, WarrantLabel.NOT_APPLICABLE, "No evidentiary object is asserted.")
    if not events:
        return _axis(WarrantAxis.OBJECT, WarrantLabel.INSUFFICIENT, "No valid cited events remain.")
    claimed = _canonical(claim.object)
    observed = set().union(*(_event_objects(event) for event in events))
    if claimed in observed:
        return _axis(WarrantAxis.OBJECT, WarrantLabel.SUPPORTED, "The claimed object exactly matches cited evidence.")

    # Directory claims may summarize explicitly cited child resources, but a
    # basename or substring alone cannot widen the scope of the evidence.
    if claimed.endswith("/") and any(item.startswith(claimed) for item in observed):
        return _axis(WarrantAxis.OBJECT, WarrantLabel.SUPPORTED, "Cited resources are children of the claimed directory.")
    if observed:
        return _axis(
            WarrantAxis.OBJECT,
            WarrantLabel.CONTRADICTED,
            f"Claimed object '{claimed}' is absent from cited objects.",
        )
    return _axis(WarrantAxis.OBJECT, WarrantLabel.INSUFFICIENT, "Cited evidence contains no resource or object field.")


def _temporal_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    if not claim.time:
        return _axis(WarrantAxis.TEMPORAL, WarrantLabel.NOT_APPLICABLE, "No time is asserted.")
    claimed = _parse_time(claim.time)
    if claimed is None:
        return _axis(
            WarrantAxis.TEMPORAL,
            WarrantLabel.INSUFFICIENT,
            "The time assertion is not an ISO-8601 instant and cannot be deterministically checked.",
        )
    observed = [_parse_time(str(event.get("timestamp", ""))) for event in events]
    observed = [item for item in observed if item is not None]
    if not observed:
        return _axis(WarrantAxis.TEMPORAL, WarrantLabel.INSUFFICIENT, "Cited evidence has no parseable timestamp.")
    try:
        if any(abs((item - claimed).total_seconds()) <= 1.0 for item in observed):
            return _axis(WarrantAxis.TEMPORAL, WarrantLabel.SUPPORTED, "The asserted time matches cited evidence.")
    except TypeError:
        return _axis(WarrantAxis.TEMPORAL, WarrantLabel.INSUFFICIENT, "Claim and evidence use incompatible timezone forms.")
    return _axis(WarrantAxis.TEMPORAL, WarrantLabel.CONTRADICTED, "The asserted time does not match cited evidence.")


def _numeric_values(event: dict[str, Any]) -> dict[str, float]:
    values: dict[str, float] = {}
    sources = [event]
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        sources.append(metadata)
    for source in sources:
        for key, raw in source.items():
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                continue
            values[_canonical(key)] = float(raw)
    return values


def _quantity_observed(quantity: Quantity, events: list[dict]) -> float | None:
    unit = quantity.unit
    if unit in {"events", "files"}:
        if unit == "files":
            file_events = [
                event for event in events
                if "file" in _canonical(event.get("action"))
                or _canonical(event.get("source_type")) == "file_access"
            ]
            return float(len(file_events))
        return float(len(events))

    numeric = [_numeric_values(event) for event in events]
    byte_keys = {"bytes", "byte_count", "file_size_bytes", "bytes_transferred", "size_bytes"}
    if unit in {"bytes", "kilobytes", "kibibytes", "megabytes", "mebibytes", "gigabytes", "gibibytes"}:
        total_bytes = sum(
            value
            for values in numeric
            for key, value in values.items()
            if key in byte_keys
        )
        if total_bytes == 0:
            return None
        divisors = {
            "bytes": 1.0,
            "kilobytes": 1000.0,
            "kibibytes": 1024.0,
            "megabytes": 1000.0 ** 2,
            "mebibytes": 1024.0 ** 2,
            "gigabytes": 1000.0 ** 3,
            "gibibytes": 1024.0 ** 3,
        }
        return total_bytes / divisors[unit]

    if unit in {"seconds", "minutes", "hours"}:
        timestamps = [_parse_time(str(event.get("timestamp", ""))) for event in events]
        timestamps = [item for item in timestamps if item is not None]
        if len(timestamps) < 2:
            return None
        duration = (max(timestamps) - min(timestamps)).total_seconds()
        divisors = {"seconds": 1.0, "minutes": 60.0, "hours": 3600.0}
        return duration / divisors[unit]
    return None


def _quantitative_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    if claim.quantity is None:
        return _axis(WarrantAxis.QUANTITATIVE, WarrantLabel.NOT_APPLICABLE, "No quantity is asserted.")
    observed = _quantity_observed(claim.quantity, events)
    if observed is None:
        return _axis(
            WarrantAxis.QUANTITATIVE,
            WarrantLabel.INSUFFICIENT,
            f"Quantity unit '{claim.quantity.unit}' cannot be recomputed from cited evidence.",
        )
    tolerance = max(claim.quantity.tolerance, abs(claim.quantity.value) * 0.01)
    if math.isclose(observed, claim.quantity.value, abs_tol=tolerance):
        return _axis(
            WarrantAxis.QUANTITATIVE,
            WarrantLabel.SUPPORTED,
            f"Recomputed value {observed:.6g} {claim.quantity.unit} matches the claim.",
        )
    return _axis(
        WarrantAxis.QUANTITATIVE,
        WarrantLabel.CONTRADICTED,
        f"Recomputed value is {observed:.6g} {claim.quantity.unit}, not {claim.quantity.value:.6g}.",
    )


def _scope_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    if not claim.scope:
        return _axis(WarrantAxis.SCOPE, WarrantLabel.NOT_APPLICABLE, "No scope qualifier is asserted.")
    scope = _canonical(claim.scope)
    if scope in {"single", "one_event", "cited_events_only"}:
        return _axis(WarrantAxis.SCOPE, WarrantLabel.SUPPORTED, "The stated scope is limited to cited evidence.")
    metadata_scopes = {
        _canonical((event.get("metadata") or {}).get("scope"))
        for event in events
        if isinstance(event.get("metadata"), dict)
    }
    if scope in metadata_scopes:
        return _axis(WarrantAxis.SCOPE, WarrantLabel.SUPPORTED, "The scope is explicitly recorded in cited metadata.")
    return _axis(
        WarrantAxis.SCOPE,
        WarrantLabel.INSUFFICIENT,
        "The cited sample does not establish the asserted population or scope.",
    )


def _resource_is_authorized(subject: str, resource: str, baselines: dict[str, dict]) -> bool | None:
    baseline = baselines.get(subject) or baselines.get(_canonical(subject))
    if not baseline:
        return None
    normal_dirs = baseline.get("normal_directories") or []
    if not normal_dirs:
        return None
    resource_path = PurePosixPath(resource)
    for directory in normal_dirs:
        try:
            resource_path.relative_to(PurePosixPath(str(directory)))
            return True
        except ValueError:
            continue
    # Being outside a normal directory is anomalous, not proof of a policy
    # violation; return unknown rather than False.
    return None


def _authorization_axis(
    claim: AtomicClaim,
    events: list[dict],
    baselines: dict[str, dict],
) -> AxisAssessment:
    if claim.authorization is None or claim.authorization == Authorization.UNKNOWN:
        return _axis(WarrantAxis.AUTHORIZATION, WarrantLabel.NOT_APPLICABLE, "No definite authorization state is asserted.")

    explicit: set[bool] = set()
    for event in events:
        metadata = event.get("metadata") or {}
        for source in (event, metadata if isinstance(metadata, dict) else {}):
            value = source.get("authorized")
            if isinstance(value, bool):
                explicit.add(value)
        if isinstance(metadata, dict) and _canonical(metadata.get("ticket_status")) == "approved":
            explicit.add(True)

    expected = claim.authorization == Authorization.AUTHORIZED
    if expected in explicit:
        return _axis(WarrantAxis.AUTHORIZATION, WarrantLabel.SUPPORTED, "Authorization is explicit in cited evidence.")
    if (not expected) in explicit:
        return _axis(WarrantAxis.AUTHORIZATION, WarrantLabel.CONTRADICTED, "Cited evidence explicitly records the opposite authorization state.")

    if expected and claim.subject and claim.object:
        baseline_result = _resource_is_authorized(claim.subject, claim.object, baselines)
        if baseline_result is True:
            return _axis(WarrantAxis.AUTHORIZATION, WarrantLabel.SUPPORTED, "The resource lies within the supplied authorized baseline.")
    return _axis(
        WarrantAxis.AUTHORIZATION,
        WarrantLabel.INSUFFICIENT,
        "Anomaly or successful access alone does not establish authorization.",
    )


def _intent_axis(claim: AtomicClaim, events: list[dict]) -> AxisAssessment:
    intent = claim.intent
    predicate_tokens = set(_canonical(claim.predicate).split("_"))
    if not intent and not predicate_tokens.intersection(_INTENT_TERMS):
        return _axis(WarrantAxis.INTENT, WarrantLabel.NOT_APPLICABLE, "No intent is asserted.")
    asserted = _canonical(intent or claim.predicate)
    explicit = {
        _canonical((event.get("metadata") or {}).get("intent"))
        for event in events
        if isinstance(event.get("metadata"), dict) and (event.get("metadata") or {}).get("intent")
    }
    if asserted in explicit:
        return _axis(WarrantAxis.INTENT, WarrantLabel.SUPPORTED, "Intent is explicit in cited evidence metadata.")
    return _axis(
        WarrantAxis.INTENT,
        WarrantLabel.INSUFFICIENT,
        "Machine events do not establish the asserted human intent.",
    )


def _linkage_tokens(events: Iterable[dict]) -> set[str]:
    tokens: set[str] = set()
    for event in events:
        metadata = event.get("metadata") or {}
        for source in (event, metadata if isinstance(metadata, dict) else {}):
            for key in ("session_id", "process_id", "trace_id", "request_id", "flow_id"):
                if source.get(key):
                    tokens.add(f"{key}:{_canonical(source[key])}")
    return tokens


def _causality_axis(
    claim: AtomicClaim,
    events: list[dict],
    claim_events: dict[str, list[dict]],
) -> AxisAssessment:
    predicate_tokens = set(_canonical(claim.predicate).split("_"))
    if not claim.causal_parent_claim_ids and not predicate_tokens.intersection(_CAUSAL_TERMS):
        return _axis(WarrantAxis.CAUSALITY, WarrantLabel.NOT_APPLICABLE, "No causal relation is asserted.")
    if not claim.causal_parent_claim_ids:
        return _axis(WarrantAxis.CAUSALITY, WarrantLabel.INSUFFICIENT, "Causal language lacks an explicit parent claim.")
    child_tokens = _linkage_tokens(events)
    for parent_id in claim.causal_parent_claim_ids:
        parent_tokens = _linkage_tokens(claim_events.get(parent_id, []))
        if child_tokens.intersection(parent_tokens):
            return _axis(
                WarrantAxis.CAUSALITY,
                WarrantLabel.SUPPORTED,
                "Parent and child evidence share an explicit session, process, trace, request, or flow identifier.",
            )
    return _axis(
        WarrantAxis.CAUSALITY,
        WarrantLabel.INSUFFICIENT,
        "Temporal proximity without an explicit linkage identifier does not establish causality.",
    )


def _modality_axis(claim: AtomicClaim, core_axes: list[AxisAssessment]) -> AxisAssessment:
    material = [
        axis for axis in core_axes
        if axis.label != WarrantLabel.NOT_APPLICABLE
        and axis.axis not in {WarrantAxis.CITATION, WarrantAxis.MODALITY}
    ]
    if claim.modality in {Modality.OBSERVED, Modality.CONFIRMED}:
        if any(axis.label == WarrantLabel.CONTRADICTED for axis in material):
            return _axis(WarrantAxis.MODALITY, WarrantLabel.CONTRADICTED, "Confirmed wording conflicts with a material cited field.")
        if any(axis.label == WarrantLabel.INSUFFICIENT for axis in material):
            return _axis(WarrantAxis.MODALITY, WarrantLabel.INSUFFICIENT, "Observed or confirmed wording exceeds the deterministically supported fields.")
        return _axis(WarrantAxis.MODALITY, WarrantLabel.SUPPORTED, "Direct wording matches all checkable material fields.")
    if claim.modality == Modality.PROBABLE:
        if any(axis.label == WarrantLabel.CONTRADICTED for axis in material):
            return _axis(WarrantAxis.MODALITY, WarrantLabel.CONTRADICTED, "Probable wording is inconsistent with cited evidence.")
        if not any(axis.label == WarrantLabel.SUPPORTED for axis in material):
            return _axis(WarrantAxis.MODALITY, WarrantLabel.INSUFFICIENT, "Probable wording lacks positive evidentiary support.")
        return _axis(WarrantAxis.MODALITY, WarrantLabel.SUPPORTED, "Probable wording has positive support and no deterministic contradiction.")
    if claim.modality == Modality.POSSIBLE:
        if any(axis.label == WarrantLabel.CONTRADICTED for axis in material):
            return _axis(WarrantAxis.MODALITY, WarrantLabel.CONTRADICTED, "The stated possibility conflicts with cited evidence.")
        return _axis(WarrantAxis.MODALITY, WarrantLabel.SUPPORTED, "Possible wording does not exceed compatible evidence.")
    return _axis(WarrantAxis.MODALITY, WarrantLabel.SUPPORTED, "Unknown modality appropriately avoids a positive claim.")


def _relation_axis(claim: AtomicClaim, core_axes: list[AxisAssessment]) -> AxisAssessment:
    material = [
        axis for axis in core_axes
        if axis.label != WarrantLabel.NOT_APPLICABLE
        and axis.axis not in {WarrantAxis.CITATION, WarrantAxis.MODALITY}
    ]
    citation = next(axis for axis in core_axes if axis.axis == WarrantAxis.CITATION)
    if citation.label != WarrantLabel.SUPPORTED:
        return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.INSUFFICIENT, "The claimed relation cannot be checked without valid citations.")

    supported = sum(axis.label == WarrantLabel.SUPPORTED for axis in material)
    contradicted = sum(axis.label == WarrantLabel.CONTRADICTED for axis in material)
    insufficient = sum(axis.label == WarrantLabel.INSUFFICIENT for axis in material)

    if claim.evidence_relation == EvidenceRelation.SUPPORTS:
        if contradicted:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.CONTRADICTED, "The model calls the evidence supportive, but a material field conflicts.")
        if insufficient:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.INSUFFICIENT, "The evidence is relevant but does not license every material field.")
        if supported:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.SUPPORTED, "The cited evidence supports all checkable material fields.")
    elif claim.evidence_relation == EvidenceRelation.CONTRADICTS:
        if contradicted:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.SUPPORTED, "At least one material field is directly contradicted as claimed.")
        return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.CONTRADICTED, "The cited evidence does not contradict a material field.")
    else:
        if insufficient and not contradicted:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.SUPPORTED, "The evidence is correctly characterized as insufficient.")
        if supported and not insufficient and not contradicted:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.CONTRADICTED, "The cited evidence directly supports the claim rather than being insufficient.")
        if contradicted:
            return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.CONTRADICTED, "The evidence directly contradicts the claim rather than merely being insufficient.")
    return _axis(WarrantAxis.EVIDENCE_RELATION, WarrantLabel.INSUFFICIENT, "The evidence relation could not be established.")


def _decision_axis(
    claim: AtomicClaim,
    output: InvestigationOutput,
    prior: list[ClaimAssessment],
) -> AxisAssessment:
    if claim.claim_type != ClaimType.DECISION:
        return _axis(WarrantAxis.DECISION, WarrantLabel.NOT_APPLICABLE, "This is not a decision claim.")
    decisive_facts = [item for item in prior if item.decisive]
    supported = [item for item in decisive_facts if item.overall_label == WarrantLabel.SUPPORTED]
    unwarranted = [item for item in decisive_facts if item.overall_label != WarrantLabel.SUPPORTED]

    if output.verdict == Verdict.INSUFFICIENT:
        if unwarranted or not decisive_facts:
            return _axis(WarrantAxis.DECISION, WarrantLabel.SUPPORTED, "Abstention is consistent with unresolved decisive evidence.")
        return _axis(WarrantAxis.DECISION, WarrantLabel.INSUFFICIENT, "All supplied decisive claims passed deterministic checks; the reason for abstention is not represented.")
    if not decisive_facts:
        return _axis(WarrantAxis.DECISION, WarrantLabel.INSUFFICIENT, "The verdict has no non-decision decisive claim.")
    if unwarranted:
        return _axis(WarrantAxis.DECISION, WarrantLabel.INSUFFICIENT, "The verdict depends on contradicted or insufficient decisive claims.")
    if supported:
        return _axis(WarrantAxis.DECISION, WarrantLabel.SUPPORTED, "The verdict is backed by deterministically supported decisive claims.")
    return _axis(WarrantAxis.DECISION, WarrantLabel.INSUFFICIENT, "Decision warrant could not be established.")


def _overall_label(claim: AtomicClaim, axes: list[AxisAssessment]) -> WarrantLabel:
    citation = next(item for item in axes if item.axis == WarrantAxis.CITATION)
    relation = next(item for item in axes if item.axis == WarrantAxis.EVIDENCE_RELATION)
    decision = next(item for item in axes if item.axis == WarrantAxis.DECISION)
    if citation.label != WarrantLabel.SUPPORTED:
        return WarrantLabel.INSUFFICIENT
    if relation.label == WarrantLabel.CONTRADICTED:
        return WarrantLabel.CONTRADICTED
    if relation.label == WarrantLabel.INSUFFICIENT:
        return WarrantLabel.INSUFFICIENT
    if claim.claim_type == ClaimType.DECISION:
        return decision.label
    return WarrantLabel.SUPPORTED


def assess_investigation(
    output: InvestigationOutput,
    events: list[dict[str, Any]],
    baselines: dict[str, dict] | None = None,
) -> WarrantReport:
    """Assess every claim against its cited events.

    The function uses only the investigation output, visible events, and
    supplied user baselines.  Rule alerts and hidden case ground truth are not
    accepted, keeping this mechanical verifier alert-blind.
    """

    baselines = baselines or {}
    event_index = {
        str(event["event_id"]): event
        for event in events
        if isinstance(event, dict) and event.get("event_id")
    }
    claim_events = {
        claim.claim_id: [event_index[event_id] for event_id in claim.cited_event_ids if event_id in event_index]
        for claim in output.claims
    }

    assessments: list[ClaimAssessment] = []
    decision_claims: list[AtomicClaim] = []
    for claim in output.claims:
        if claim.claim_type == ClaimType.DECISION:
            decision_claims.append(claim)
            continue
        cited = claim_events[claim.claim_id]
        axes = [
            _citation_axis(claim, event_index),
            _actor_axis(claim, cited),
            _action_axis(claim, cited),
            _object_axis(claim, cited),
            _temporal_axis(claim, cited),
            _quantitative_axis(claim, cited),
            _scope_axis(claim, cited),
            _authorization_axis(claim, cited, baselines),
            _intent_axis(claim, cited),
            _causality_axis(claim, cited, claim_events),
        ]
        axes.append(_modality_axis(claim, axes))
        axes.append(_axis(WarrantAxis.DECISION, WarrantLabel.NOT_APPLICABLE, "This is not a decision claim."))
        axes.append(_relation_axis(claim, axes))
        invalid = [event_id for event_id in claim.cited_event_ids if event_id not in event_index]
        assessments.append(ClaimAssessment(
            claim_id=claim.claim_id,
            decisive=claim.decisive,
            overall_label=_overall_label(claim, axes),
            valid_cited_event_ids=[event_id for event_id in claim.cited_event_ids if event_id in event_index],
            invalid_cited_event_ids=invalid,
            axes=axes,
        ))

    for claim in decision_claims:
        cited = claim_events[claim.claim_id]
        axes = [
            _citation_axis(claim, event_index),
            _actor_axis(claim, cited),
            _action_axis(claim, cited),
            _object_axis(claim, cited),
            _temporal_axis(claim, cited),
            _quantitative_axis(claim, cited),
            _scope_axis(claim, cited),
            _authorization_axis(claim, cited, baselines),
            _intent_axis(claim, cited),
            _causality_axis(claim, cited, claim_events),
        ]
        axes.append(_modality_axis(claim, axes))
        axes.append(_decision_axis(claim, output, assessments))
        # The decision relation is evaluated by the decision axis because its
        # predicate is not an event action.
        decision_assessment = axes[-1]
        axes.append(_axis(
            WarrantAxis.EVIDENCE_RELATION,
            decision_assessment.label,
            decision_assessment.reason,
        ))
        invalid = [event_id for event_id in claim.cited_event_ids if event_id not in event_index]
        assessments.append(ClaimAssessment(
            claim_id=claim.claim_id,
            decisive=True,
            overall_label=_overall_label(claim, axes),
            valid_cited_event_ids=[event_id for event_id in claim.cited_event_ids if event_id in event_index],
            invalid_cited_event_ids=invalid,
            axes=axes,
        ))

    total_citations = sum(len(claim.cited_event_ids) for claim in output.claims)
    valid_citations = sum(len(item.valid_cited_event_ids) for item in assessments)
    cited_claims = sum(bool(claim.cited_event_ids) for claim in output.claims)
    decisive = [item for item in assessments if item.decisive]
    unwarranted_decisive = [
        item for item in decisive if item.overall_label != WarrantLabel.SUPPORTED
    ]
    return WarrantReport(
        case_id=output.case_id,
        total_claims=len(assessments),
        decisive_claims=len(decisive),
        supported_claims=sum(item.overall_label == WarrantLabel.SUPPORTED for item in assessments),
        contradicted_claims=sum(item.overall_label == WarrantLabel.CONTRADICTED for item in assessments),
        insufficient_claims=sum(item.overall_label == WarrantLabel.INSUFFICIENT for item in assessments),
        citation_validity=(valid_citations / total_citations if total_citations else 0.0),
        citation_completeness=(cited_claims / len(output.claims) if output.claims else 0.0),
        unwarranted_decisive_claim_rate=(
            len(unwarranted_decisive) / len(decisive) if decisive else 1.0
        ),
        assessments=assessments,
    )


def _explicit_counterevidence_reason(
    event: dict[str, Any],
    suspect: str | None,
    baselines: dict[str, dict],
) -> tuple[str, bool] | None:
    action = _canonical(event.get("action"))
    status = _canonical(event.get("status"))
    metadata = event.get("metadata") or {}
    metadata = metadata if isinstance(metadata, dict) else {}

    if action in _ACTION_EQUIVALENTS.get("login_failed", set()) and status in {"failure", "failed", "denied"}:
        return ("Authentication attempt failed; it does not establish successful access.", True)
    if metadata.get("authorized") is True:
        return ("The event explicitly records authorized activity.", True)
    if metadata.get("authorized") is False:
        # Explicit event-level authorization evidence outranks a broad baseline
        # such as an ordinarily permitted directory.
        return None
    if _canonical(metadata.get("ticket_status")) == "approved" or metadata.get("ticket_approved") is True:
        return ("An approved ticket covers the activity.", True)
    if action in _ACTION_EQUIVALENTS.get("privilege_revert", set()):
        return ("Privileges were reverted, consistent with bounded maintenance.", False)
    if metadata.get("destination_internal") is True:
        return ("The transfer destination is explicitly internal to the organization.", False)
    if metadata.get("mfa_verified") is True and metadata.get("expected_device") is True:
        return ("MFA and expected-device evidence support legitimate account control.", False)

    user = str(event.get("user") or "")
    resource = str(event.get("resource") or "")
    if suspect and user == suspect and resource:
        authorized = _resource_is_authorized(suspect, resource, baselines)
        if authorized is True:
            return ("The resource is within the supplied authorized baseline.", False)
    return None


def find_counterevidence(
    output: InvestigationOutput,
    events: list[dict[str, Any]],
    baselines: dict[str, dict] | None = None,
) -> CounterEvidenceReport:
    """Find explicit, alert-blind evidence that weakens an attack hypothesis."""

    baselines = baselines or {}
    candidates: list[CounterEvidenceCandidate] = []
    if output.verdict == Verdict.YES:
        # Earlier failed or authorized events remain material context, but they
        # cannot defeat later evidence that explicitly records a successful
        # unauthorized action. Treat them as outcome-decisive only when no such
        # independent incident evidence is visible.
        explicit_incident_evidence = any(
            _canonical(event.get("status")) in {"success", "successful"}
            and isinstance(event.get("metadata"), dict)
            and (event.get("metadata") or {}).get("authorized") is False
            for event in events
        )
        for event in events:
            event_id = event.get("event_id")
            if not event_id:
                continue
            action = _canonical(event.get("action"))
            if (
                explicit_incident_evidence
                and action in _ACTION_EQUIVALENTS.get("login_failed", set())
            ):
                continue
            found = _explicit_counterevidence_reason(event, output.suspect, baselines)
            if found:
                reason, decisive = found
                candidates.append(CounterEvidenceCandidate(
                    event_id=str(event_id),
                    reason=reason,
                    decisive=decisive and not explicit_incident_evidence,
                ))

    available_ids = {candidate.event_id for candidate in candidates}
    cited_ids = sorted(available_ids.intersection(output.evidence_against))
    missed = sorted(available_ids.difference(output.evidence_against))
    decisive_missed = sorted(
        candidate.event_id
        for candidate in candidates
        if candidate.decisive and candidate.event_id in missed
    )
    recall = len(cited_ids) / len(available_ids) if available_ids else None
    return CounterEvidenceReport(
        available=candidates,
        cited_event_ids=cited_ids,
        missed_event_ids=missed,
        decisive_missed_event_ids=decisive_missed,
        recall=recall,
    )


def apply_abstention_policy(
    output: InvestigationOutput,
    warrant: WarrantReport,
    counterevidence: CounterEvidenceReport,
    *,
    minimum_confidence: float = 0.65,
) -> ReviewDecision:
    """Apply a fixed, conservative review policy to a model output."""

    reasons: list[str] = []
    if output.verdict == Verdict.INSUFFICIENT or output.abstain:
        reasons.append("The generator already abstained.")
    if output.overall_confidence < minimum_confidence:
        reasons.append(
            f"Overall confidence {output.overall_confidence:.3f} is below the fixed threshold {minimum_confidence:.3f}."
        )
    unwarranted = [
        item.claim_id
        for item in warrant.assessments
        if item.decisive and item.overall_label != WarrantLabel.SUPPORTED
    ]
    if unwarranted:
        reasons.append(f"Decisive claims lack warrant: {', '.join(unwarranted)}.")
    invalid = sorted({
        event_id
        for item in warrant.assessments
        for event_id in item.invalid_cited_event_ids
    })
    if invalid:
        reasons.append(f"Invalid citations are present: {', '.join(invalid)}.")
    if counterevidence.decisive_missed_event_ids:
        reasons.append(
            "Decisive counterevidence was omitted: "
            + ", ".join(counterevidence.decisive_missed_event_ids)
            + "."
        )

    disposition = ReviewDisposition.ABSTAIN if reasons else ReviewDisposition.ALLOW
    reviewed = Verdict.INSUFFICIENT if reasons else output.verdict
    return ReviewDecision(
        disposition=disposition,
        original_verdict=output.verdict,
        reviewed_verdict=reviewed,
        reasons=reasons,
        coverage=0.0 if reasons else 1.0,
    )
