from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path


PAPER_GENERATOR = (
    Path(__file__).resolve().parents[2]
    / "conference_paper"
    / "generate_paper_artifacts.py"
)


def _load_generator():
    spec = importlib.util.spec_from_file_location("paper_artifacts", PAPER_GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_human_macro_export_is_bound_to_analysis_hash(tmp_path: Path) -> None:
    generator = _load_generator()
    analysis = {
        "sample": {"selected_claims": 400, "population_claims": 1000},
        "inter_rater": {
            "overall": {
                "agreement": 0.8,
                "design_weighted_agreement": 0.75,
                "cohen_kappa": 0.6,
                "design_weighted_cohen_kappa": 0.55,
            },
            "materiality_decisive": {"design_weighted_agreement": 0.85},
        },
        "mechanical_validation": {
            "overall": {
                "agreement": 0.7,
                "design_weighted_agreement": 0.65,
                "design_weighted_cohen_kappa": 0.5,
            },
            "materiality_decisive": {"design_weighted_agreement": 0.8},
            "materially_unwarranted_flag": {
                "design_weighted_precision": 0.8,
                "design_weighted_recall": 0.7,
                "design_weighted_specificity": 0.9,
                "design_weighted_f1": 0.746666,
            },
        },
        "human_primary_endpoint": {
            "reference_condition": "llm_events_plus_alerts",
            "intervention_condition": "generator_verifier_abstention",
            "selected_claims_joined_to_primary_conditions": 210,
            "condition_estimates": {
                "llm_events_plus_alerts": {
                    "surfaced_unwarranted_decisive_claims_per_base_case": 0.4
                },
                "generator_verifier_abstention": {
                    "surfaced_unwarranted_decisive_claims_per_base_case": 0.1
                },
            },
            "contrast_intervention_minus_reference": {
                "estimate": -0.3,
                "confidence_interval": [-0.5, -0.1],
            },
        },
        "annotation_timing": {
            "annotator_1": {
                "median_seconds_per_item": 120.0,
                "total_hours": 14.0,
            },
            "annotator_2": {
                "median_seconds_per_item": 150.0,
                "total_hours": 16.0,
            },
            "adjudicator": {
                "median_seconds_per_item": 90.0,
                "total_hours": 10.0,
            },
        },
        "source_sha256": {"records": "f" * 64},
        "bootstrap": {
            "metrics": {
                "inter_rater_overall_agreement": {
                    "confidence_interval": [0.7, 0.8]
                },
                "mechanical_overall_agreement": {
                    "confidence_interval": [0.6, 0.7]
                },
                "materially_unwarranted_precision": {
                    "confidence_interval": [0.7, 0.9]
                },
                "materially_unwarranted_recall": {
                    "confidence_interval": [0.6, 0.8]
                },
            }
        },
    }
    source = tmp_path / "human_analysis.json"
    output = tmp_path / "human_results.tex"
    source.write_text(json.dumps(analysis))

    generator.write_human_result_macros(source, output)

    text = output.read_text()
    assert "human_analysis_sha256=" in text
    assert "source_records_sha256=" + "f" * 64 in text
    assert r"\newcommand{\HumanSampleClaims}{400}" in text
    assert r"\newcommand{\MechanicalFlagRecall}{70.0\%}" in text
    assert r"\newcommand{\HumanPrimaryUnsafeDifference}{-.300}" in text
    assert r"\newcommand{\AnnotationTotalHours}{40.000}" in text


def test_generated_table_inputs_own_their_terminal_booktabs_rule(
    tmp_path: Path,
) -> None:
    r"""Prevent XeTeX from seeing caller-side \bottomrule after row input."""

    generator = _load_generator()
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    analysis = {
        "by_variant": {
            "canonical": {
                "conditions": {
                    "llm_events_plus_alerts": {
                        "verdict_accuracy": 1.0,
                        "surfaced_unwarranted_decisive_claims_per_case": 0.0,
                    },
                    "generator_verifier_abstention": {
                        "coverage": 1.0,
                        "surfaced_unwarranted_decisive_claims_per_case": 0.0,
                    },
                }
            }
        },
        "variant_contrasts": {},
        "mechanical_axis_profiles": {
            "llm_events_plus_alerts": {
                "decisive_claims": {
                    "citation": {"applicable": 1, "unwarranted_rate": 0.0}
                }
            }
        },
    }
    (run_dir / "analysis.json").write_text(json.dumps(analysis))
    variant_rows = tmp_path / "variant_rows.tex"
    axis_rows = tmp_path / "axis_rows.tex"

    generator.write_variant_rows(run_dir, variant_rows)
    generator.write_axis_rows(run_dir, axis_rows)

    assert variant_rows.read_text().rstrip().endswith(r"\bottomrule")
    assert axis_rows.read_text().rstrip().endswith(r"\bottomrule")


def test_simulated_macros_preserve_non_expert_validity_boundary(
    tmp_path: Path,
) -> None:
    generator = _load_generator()
    analysis = {
        "validity_boundary": "AI sensitivity study; not expert validation",
        "sample": {"claims": 400, "population_claims": 11284},
        "reviewers": [
            {"panel_role": "consensus"},
            {"panel_role": "consensus"},
            {"panel_role": "consensus"},
        ],
        "panel": {
            "items_with_any_disagreement": 120,
            "items_with_overall_disagreement": 80,
            "items_with_materiality_disagreement": 40,
        },
        "consensus_vs_mechanical_proxy": {
            "overall": {
                "design_weighted_agreement": 0.7,
                "design_weighted_cohen_kappa": 0.5,
            },
            "materially_unwarranted_flag": {
                "design_weighted_precision": 0.6,
                "design_weighted_recall": 0.8,
            },
        },
        "simulated_primary_endpoint": {
            "reference_condition": "llm_events_plus_alerts",
            "intervention_condition": "generator_verifier_abstention",
            "selected_claims_joined_to_primary_conditions": 210,
            "condition_estimates": {
                "llm_events_plus_alerts": {
                    "surfaced_unwarranted_decisive_claims_per_base_case": 0.4
                },
                "generator_verifier_abstention": {
                    "surfaced_unwarranted_decisive_claims_per_base_case": 0.1
                },
            },
            "contrast_intervention_minus_reference": {
                "estimate": -0.3,
                "confidence_interval": [-0.5, -0.1],
            },
        },
        "source_sha256": {"records": "e" * 64},
    }
    source = tmp_path / "simulated_analysis.json"
    output = tmp_path / "simulated_results.tex"
    source.write_text(json.dumps(analysis))

    generator.write_simulated_result_macros(source, output)

    text = output.read_text()
    assert "not expert validation" in text
    assert r"\newcommand{\SimPanelAnyDisagreement}{30.0\%}" in text
    assert r"\newcommand{\SimMechanicalWeightedAgreement}{70.0\%}" in text
    assert r"\newcommand{\SimPrimaryUnsafeDifference}{-.300}" in text


def test_external_macros_report_failure_inclusive_validity(tmp_path: Path) -> None:
    generator = _load_generator()
    run_dir = tmp_path / "external"
    run_dir.mkdir()
    condition = {
        "valid_n": 2,
        "n": 4,
        "verdict_accuracy": 0.25,
        "coverage": 0.25,
        "attack_recall": 0.5,
        "benign_rejection": 0.0,
        "surfaced_unwarranted_decisive_claims_per_case": 0.25,
        "citation_validity": 1.0,
    }
    analysis = {
        "run_id": "external-test",
        "record_count": 12,
        "base_case_count": 1,
        "conditions": {
            "llm_events_plus_alerts": condition,
            "generator_verifier": condition,
            "generator_verifier_abstention": condition,
        },
    }
    (run_dir / "analysis.json").write_text(json.dumps(analysis))
    record = {
        "case_id": "window-1",
        "repetition": 0,
        "evaluation_label_semantics": (
            "latent_incident_label_not_visible_evidence_warrant"
        ),
    }
    (run_dir / "records.jsonl").write_text(json.dumps(record) + "\n")
    output = tmp_path / "external_results.tex"

    generator.write_external_result_macros(run_dir, output)

    text = output.read_text()
    assert r"\newcommand{\ExternalOperationalValidity}{50.0\%}" in text
    assert r"\newcommand{\ExternalOperationalFailure}{50.0\%}" in text


def test_every_manuscript_citation_has_bibtex_and_audit_entry() -> None:
    paper_dir = PAPER_GENERATOR.parent
    manuscript = (paper_dir / "paper.tex").read_text()
    bibliography = (paper_dir / "references.bib").read_text()
    audit = (paper_dir / "REFERENCE_AUDIT.md").read_text()
    cited = {
        key.strip()
        for group in re.findall(r"\\cite\{([^}]+)\}", manuscript)
        for key in group.split(",")
    }
    bib_keys = set(re.findall(r"^@\w+\{([^,]+),", bibliography, re.MULTILINE))
    audited = set(re.findall(r"^\| `([^`]+)` \|", audit, re.MULTILINE))

    assert cited <= bib_keys
    assert audited == cited
    assert len(cited) == 34
