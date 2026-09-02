"""Transparent and classical baselines for the warrant benchmark."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, f1_score, matthews_corrcoef
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

from app.ingestion.warrant_benchmark import BENCHMARK_DIR, PROJECT_ROOT, load_cases

BASELINE_RESULTS_PATH = BENCHMARK_DIR / "baseline_predictions.jsonl"
BASELINE_SUMMARY_PATH = BENCHMARK_DIR / "baseline_summary.json"
BASELINE_VERSION = "warrant-baselines-v1.0"


@dataclass(frozen=True)
class BaselinePrediction:
    case_id: str
    base_case_id: str
    family: str
    split: str
    variant: str
    model: str
    expected_verdict: str
    predicted_verdict: str
    expected_attack: bool
    predicted_attack: bool
    attack_probability: float
    confidence: float
    exact_correct: bool
    binary_correct: bool
    reason: str


def _canonical(value: Any) -> str:
    text = str(value or "").strip().lower()
    return re.sub(r"[^a-z0-9/_.:-]+", "_", text).strip("_")


def _action(event: dict[str, Any]) -> str:
    return _canonical(
        event.get("action")
        or event.get("operation")
        or (event.get("metadata") or {}).get("operation")
        or (event.get("metadata") or {}).get("action")
    )


def _user(event: dict[str, Any]) -> str:
    return _canonical(event.get("user") or event.get("principal"))


def _resource(event: dict[str, Any]) -> str:
    return _canonical(event.get("resource") or event.get("object"))


def _metadata(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("metadata")
    return value if isinstance(value, dict) else {}


def _status(event: dict[str, Any]) -> str:
    return _canonical(event.get("status"))


def _is_success(event: dict[str, Any]) -> bool:
    return _status(event) in {"success", "succeeded", "ok", "completed", ""}


def _is_failed_login(event: dict[str, Any]) -> bool:
    return _action(event) in {"login_failed", "failed_login", "authentication_failure"}


def _is_successful_login(event: dict[str, Any]) -> bool:
    return _action(event) in {"login", "login_success", "authenticate"} and _is_success(event)


def _is_off_hours(event: dict[str, Any]) -> bool:
    try:
        hour = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00")).hour
    except (KeyError, TypeError, ValueError):
        return False
    return hour < 7 or hour >= 20


def _numeric_metadata(event: dict[str, Any], keys: set[str]) -> float:
    total = 0.0
    for source in (event, _metadata(event)):
        for key, value in source.items():
            if _canonical(key) in keys and isinstance(value, (int, float)) and not isinstance(value, bool):
                total += float(value)
    return total


_TRACKED_ACTIONS = (
    "login",
    "login_failed",
    "session_ip_change",
    "file_read",
    "file_download",
    "file_upload",
    "archive_create",
    "network_transfer",
    "privilege_change",
    "privilege_revert",
    "database_export",
    "resource_delete",
    "backup_disable",
    "log_delete",
    "ticket_approved",
    "travel_approved",
    "backup_job_approved",
    "period_close_approved",
    "test_scope_approved",
    "account_review_complete",
)


def extract_features(case: dict[str, Any], *, include_alerts: bool = True) -> dict[str, float]:
    """Extract a fixed, human-auditable feature vector from visible data."""

    events = case["events"]
    actions = Counter(_action(event) for event in events)
    users = {_user(event) for event in events if _user(event)}
    ips = {_canonical(event.get("source_ip")) for event in events if event.get("source_ip")}
    sessions: dict[str, set[str]] = {}
    explicit_authorized = 0
    explicit_unauthorized = 0
    external_transfers = 0
    internal_transfers = 0
    prompt_injection_markers = 0
    approved_context = 0
    denied_context = 0
    for event in events:
        metadata = _metadata(event)
        authorized = metadata.get("authorized")
        explicit_authorized += authorized is True
        explicit_unauthorized += authorized is False
        if metadata.get("destination_internal") is False:
            external_transfers += 1
        elif metadata.get("destination_internal") is True:
            internal_transfers += 1
        approved_context += (
            _canonical(metadata.get("ticket_status")) == "approved"
            or metadata.get("ticket_approved") is True
        )
        denied_context += _canonical(metadata.get("ticket_status")) in {"denied", "rejected"}
        prompt_injection_markers += metadata.get("untrusted_content") is True
        session = _canonical(event.get("session_id"))
        ip = _canonical(event.get("source_ip"))
        if session and ip:
            sessions.setdefault(session, set()).add(ip)

    features: dict[str, float] = {
        "event_count": float(len(events)),
        "unique_users": float(len(users)),
        "unique_source_ips": float(len(ips)),
        "unique_sessions": float(len(sessions)),
        "sessions_with_ip_change": float(sum(len(values) > 1 for values in sessions.values())),
        "failed_login_count": float(sum(_is_failed_login(event) for event in events)),
        "successful_login_count": float(sum(_is_successful_login(event) for event in events)),
        "successful_unauthorized_count": float(sum(
            _metadata(event).get("authorized") is False and _is_success(event)
            for event in events
        )),
        "explicit_authorized_count": float(explicit_authorized),
        "explicit_unauthorized_count": float(explicit_unauthorized),
        "approved_context_count": float(approved_context),
        "denied_context_count": float(denied_context),
        "external_transfer_count": float(external_transfers),
        "internal_transfer_count": float(internal_transfers),
        "off_hours_count": float(sum(_is_off_hours(event) for event in events)),
        "total_bytes": float(sum(
            _numeric_metadata(event, {"bytes", "file_size_bytes", "bytes_transferred", "size_bytes"})
            for event in events
        )),
        "schema_drift_count": float(sum("operation" in event or "principal" in event for event in events)),
        "prompt_injection_marker_count": float(prompt_injection_markers),
    }
    for action in _TRACKED_ACTIONS:
        features[f"action__{action}"] = float(actions[action])

    if include_alerts:
        alerts = case.get("alerts") or []
        features.update({
            "alert_count": float(len(alerts)),
            "critical_alert_count": float(sum(_canonical(alert.get("severity")) == "critical" for alert in alerts)),
            "high_alert_count": float(sum(_canonical(alert.get("severity")) == "high" for alert in alerts)),
            "unique_alert_actors": float(len({_canonical(alert.get("actor")) for alert in alerts if alert.get("actor")})),
        })
    else:
        features.update({
            "alert_count": 0.0,
            "critical_alert_count": 0.0,
            "high_alert_count": 0.0,
            "unique_alert_actors": 0.0,
        })
    return features


_HARMFUL_ACTIONS = {
    "file_download", "get_object", "network_transfer", "database_export",
    "privilege_change", "resource_delete", "backup_disable", "log_delete",
    "assume_role", "archive_create",
}


def tuned_rule_verdict(case: dict[str, Any]) -> tuple[str, float, str]:
    """A conservative, transparent verdict rule frozen before test scoring."""

    events = case["events"]
    successful_logins = [event for event in events if _is_successful_login(event)]
    failed_logins = [event for event in events if _is_failed_login(event)]
    unauthorized = [
        event for event in events
        if _metadata(event).get("authorized") is False and _is_success(event)
    ]
    unauthorized_harm = [event for event in unauthorized if _action(event) in _HARMFUL_ACTIONS]
    external_transfer = [
        event for event in events
        if _action(event) == "network_transfer"
        and _metadata(event).get("destination_internal") is False
        and _metadata(event).get("authorized") is False
    ]
    ip_change = [
        event for event in events
        if _action(event) == "session_ip_change"
        and _metadata(event).get("authorized") is False
    ]

    if external_transfer or unauthorized_harm:
        return "YES", 0.95, "Explicitly unauthorized harmful action or external transfer."
    if ip_change and any(_action(event) in _HARMFUL_ACTIONS for event in unauthorized):
        return "YES", 0.90, "Unauthorized mid-session identity change precedes a harmful action."
    if any(_metadata(event).get("authorized") is False for event in successful_logins):
        later_harm = any(_action(event) in _HARMFUL_ACTIONS and _is_success(event) for event in events)
        if later_harm:
            return "YES", 0.90, "Unauthorized successful access is followed by a harmful action."

    explicit_benign = any(
        _metadata(event).get("authorized") is True
        and (
            _canonical(_metadata(event).get("ticket_status")) == "approved"
            or _action(event) in {
                "travel_approved", "backup_job_approved", "period_close_approved",
                "test_scope_approved", "account_review_complete", "privilege_revert",
            }
        )
        for event in events
    )
    any_unauthorized = any(_metadata(event).get("authorized") is False for event in events)
    if explicit_benign and not any_unauthorized:
        return "NO", 0.90, "Explicit authorization or closure evidence is present with no unauthorized event."
    failed_attempts_resolved = any(
        _action(event) == "account_review_complete"
        and _metadata(event).get("successful_attacker_login") is False
        for event in events
    )
    if failed_logins and not successful_logins and not unauthorized_harm and failed_attempts_resolved:
        return "NO", 0.85, "Failed attempts are paired with an explicit review finding no successful attacker login."
    return "INSUFFICIENT", 0.50, "Visible evidence does not meet a fixed YES or NO rule."


def _record(case: dict[str, Any], model: str, verdict: str, probability: float, reason: str) -> BaselinePrediction:
    expected = case["ground_truth"]["warranted_verdict"]
    predicted_attack = verdict == "YES"
    expected_attack = expected == "YES"
    confidence = probability if predicted_attack else 1.0 - probability
    return BaselinePrediction(
        case_id=case["case_id"],
        base_case_id=case["base_case_id"],
        family=case["family"],
        split=case["split"],
        variant=case["variant"],
        model=model,
        expected_verdict=expected,
        predicted_verdict=verdict,
        expected_attack=expected_attack,
        predicted_attack=predicted_attack,
        attack_probability=float(probability),
        confidence=float(confidence),
        exact_correct=verdict == expected,
        binary_correct=predicted_attack == expected_attack,
        reason=reason,
    )


def _constant_predictions(cases: list[dict[str, Any]], attack: bool) -> list[BaselinePrediction]:
    verdict = "YES" if attack else "NO"
    probability = 1.0 if attack else 0.0
    model = "always_attack" if attack else "always_benign"
    return [
        _record(case, model, verdict, probability, f"Fixed {verdict} baseline.")
        for case in cases
    ]


def _rule_predictions(cases: list[dict[str, Any]]) -> list[BaselinePrediction]:
    records = []
    for case in cases:
        verdict, confidence, reason = tuned_rule_verdict(case)
        if verdict == "YES":
            probability = confidence
        elif verdict == "NO":
            probability = 1.0 - confidence
        else:
            probability = 0.5
        records.append(_record(case, "tuned_rules", verdict, probability, reason))
    return records


def _fit_ml_predictions(
    cases: list[dict[str, Any]],
    *,
    model_name: str,
    include_alerts: bool,
    seed: int,
) -> list[BaselinePrediction]:
    training = [case for case in cases if case["split"] == "development"]
    test = [case for case in cases if case["split"] == "test"]
    vectorizer = DictVectorizer(sparse=False, sort=True)
    x_train = vectorizer.fit_transform([
        extract_features(case, include_alerts=include_alerts) for case in training
    ])
    x_test = vectorizer.transform([
        extract_features(case, include_alerts=include_alerts) for case in test
    ])
    y_train = np.asarray([
        int(case["ground_truth"]["warranted_verdict"] == "YES") for case in training
    ])

    if model_name.startswith("logistic_regression"):
        estimator: Any = Pipeline([
            ("scale", StandardScaler()),
            ("model", LogisticRegression(
                class_weight="balanced",
                max_iter=2000,
                random_state=seed,
                C=1.0,
            )),
        ])
        fit_kwargs: dict[str, Any] = {}
    elif model_name.startswith("gradient_boosted_trees"):
        estimator = HistGradientBoostingClassifier(
            learning_rate=0.08,
            max_iter=150,
            max_leaf_nodes=15,
            l2_regularization=1.0,
            random_state=seed,
        )
        fit_kwargs = {"sample_weight": compute_sample_weight("balanced", y_train)}
    else:
        raise ValueError(model_name)

    estimator.fit(x_train, y_train, **fit_kwargs)
    probabilities = estimator.predict_proba(x_test)[:, 1]
    records = []
    for case, probability in zip(test, probabilities, strict=True):
        verdict = "YES" if probability >= 0.5 else "NO"
        records.append(_record(
            case,
            model_name,
            verdict,
            float(probability),
            "Development-trained structured-feature classifier at fixed threshold 0.5.",
        ))
    return records


def run_baselines(cases: list[dict[str, Any]] | None = None, *, seed: int = 20260902) -> list[BaselinePrediction]:
    cases = cases or load_cases()
    records: list[BaselinePrediction] = []
    records.extend(_constant_predictions(cases, attack=True))
    records.extend(_constant_predictions(cases, attack=False))
    records.extend(_rule_predictions(cases))
    records.extend(_fit_ml_predictions(
        cases,
        model_name="logistic_regression_events_alerts",
        include_alerts=True,
        seed=seed,
    ))
    records.extend(_fit_ml_predictions(
        cases,
        model_name="gradient_boosted_trees_events_alerts",
        include_alerts=True,
        seed=seed,
    ))
    return records


def summarize_predictions(records: list[BaselinePrediction]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "baseline_version": BASELINE_VERSION,
        "independent_unit": "base_case",
        "models": {},
    }
    by_model: dict[str, list[BaselinePrediction]] = {}
    for record in records:
        if record.split == "test":
            by_model.setdefault(record.model, []).append(record)
    for model, model_records in sorted(by_model.items()):
        expected = np.asarray([record.expected_attack for record in model_records], dtype=int)
        predicted = np.asarray([record.predicted_attack for record in model_records], dtype=int)
        exact = np.asarray([record.exact_correct for record in model_records], dtype=float)
        attack_mask = expected == 1
        benign_mask = expected == 0
        summary["models"][model] = {
            "case_variants": len(model_records),
            "base_cases": len({record.base_case_id for record in model_records}),
            "exact_three_way_accuracy": float(exact.mean()),
            "binary_accuracy": float((expected == predicted).mean()),
            "balanced_accuracy": float(balanced_accuracy_score(expected, predicted)),
            "macro_f1": float(f1_score(expected, predicted, average="macro", zero_division=0)),
            "matthews_correlation": float(matthews_corrcoef(expected, predicted)),
            "attack_recall": float(predicted[attack_mask].mean()) if attack_mask.any() else None,
            "false_positive_rate": float(predicted[benign_mask].mean()) if benign_mask.any() else None,
            "abstention_rate": float(np.mean([
                record.predicted_verdict == "INSUFFICIENT" for record in model_records
            ])),
            "mean_confidence": float(np.mean([record.confidence for record in model_records])),
        }
    return summary


def write_baseline_results(
    records: list[BaselinePrediction],
    *,
    predictions_path: Path = BASELINE_RESULTS_PATH,
    summary_path: Path = BASELINE_SUMMARY_PATH,
) -> dict[str, Any]:
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(asdict(record), sort_keys=True, separators=(",", ":")) for record in records]
    predictions_path.write_text("\n".join(lines) + "\n")
    summary = summarize_predictions(records)
    try:
        recorded_path = predictions_path.relative_to(PROJECT_ROOT)
    except ValueError:
        recorded_path = predictions_path
    summary["predictions_path"] = str(recorded_path)
    summary["prediction_records"] = len(records)
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary
