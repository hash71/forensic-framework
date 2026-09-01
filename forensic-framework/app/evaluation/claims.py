"""Typed output contract for atomic forensic claims.

The v1 pipeline treated an event identifier attached to free-form prose as a
supported claim.  The v2 contract makes the proposition itself machine
inspectable so citation validity, evidential warrant, and decision correctness
can be evaluated separately.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "forensic-claim-v2.0"


class StrictModel(BaseModel):
    """Base model that rejects silent schema drift."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Verdict(str, Enum):
    YES = "YES"
    NO = "NO"
    INSUFFICIENT = "INSUFFICIENT"


class ClaimType(str, Enum):
    OBSERVATION = "observation"
    DERIVED_FACT = "derived_fact"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"


class Modality(str, Enum):
    OBSERVED = "observed"
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


class EvidenceRelation(str, Enum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    INSUFFICIENT = "insufficient"


class Authorization(str, Enum):
    AUTHORIZED = "authorized"
    UNAUTHORIZED = "unauthorized"
    UNKNOWN = "unknown"


class Quantity(StrictModel):
    """A recomputable quantitative assertion."""

    value: float
    unit: str = Field(min_length=1, max_length=32)
    tolerance: float = Field(default=0.0, ge=0.0)

    @field_validator("unit")
    @classmethod
    def normalize_unit(cls, value: str) -> str:
        aliases = {
            "byte": "bytes",
            "b": "bytes",
            "kb": "kilobytes",
            "kib": "kibibytes",
            "mb": "megabytes",
            "mib": "mebibytes",
            "gb": "gigabytes",
            "gib": "gibibytes",
            "sec": "seconds",
            "second": "seconds",
            "min": "minutes",
            "minute": "minutes",
            "event": "events",
            "file": "files",
        }
        unit = value.strip().lower()
        return aliases.get(unit, unit)


class AtomicClaim(StrictModel):
    """One independently checkable forensic proposition."""

    claim_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
    claim_type: ClaimType
    subject: str | None = None
    predicate: str = Field(min_length=1, max_length=128)
    object: str | None = None
    time: str | None = None
    quantity: Quantity | None = None
    scope: str | None = None
    modality: Modality
    authorization: Authorization | None = None
    intent: str | None = None
    causal_parent_claim_ids: list[str] = Field(default_factory=list)
    cited_event_ids: list[str] = Field(default_factory=list)
    evidence_relation: EvidenceRelation
    confidence: float = Field(ge=0.0, le=1.0)
    decisive: bool = False
    rationale: str = Field(default="", max_length=2000)

    @field_validator("cited_event_ids", "causal_parent_claim_ids")
    @classmethod
    def unique_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("identifier lists must not contain duplicates")
        return values

    @model_validator(mode="after")
    def enforce_claim_contract(self) -> AtomicClaim:
        if self.claim_type == ClaimType.OBSERVATION and self.modality not in {
            Modality.OBSERVED,
            Modality.CONFIRMED,
        }:
            raise ValueError("observation claims must use observed or confirmed modality")
        if self.claim_type == ClaimType.DECISION and not self.decisive:
            raise ValueError("decision claims must be marked decisive")
        if self.evidence_relation == EvidenceRelation.SUPPORTS and not self.cited_event_ids:
            raise ValueError("a claim asserting evidential support must cite at least one event")
        return self


class AlternativeHypothesis(StrictModel):
    hypothesis: str = Field(min_length=1, max_length=1000)
    cited_event_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class InvestigationOutput(StrictModel):
    """Authoritative v2 investigation record.

    Narrative prose may be rendered from this object for a human reader, but it
    is intentionally excluded from the evaluation contract.
    """

    schema_version: str = SCHEMA_VERSION
    case_id: str = Field(min_length=1, max_length=128)
    verdict: Verdict
    suspect: str | None = None
    claims: list[AtomicClaim]
    evidence_for: list[str] = Field(default_factory=list)
    evidence_against: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    alternative_hypotheses: list[AlternativeHypothesis] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0.0, le=1.0)
    abstain: bool = False
    abstention_reason: str | None = None

    @field_validator("evidence_for", "evidence_against")
    @classmethod
    def unique_evidence_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("evidence lists must not contain duplicates")
        return values

    @model_validator(mode="after")
    def enforce_investigation_contract(self) -> InvestigationOutput:
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("claim_id values must be unique within an investigation")
        known_claim_ids = set(claim_ids)
        unknown_parents = sorted({
            parent
            for claim in self.claims
            for parent in claim.causal_parent_claim_ids
            if parent not in known_claim_ids
        })
        if unknown_parents:
            raise ValueError(f"unknown causal parent claim ids: {unknown_parents}")
        if self.abstain and self.verdict != Verdict.INSUFFICIENT:
            raise ValueError("an abstaining output must use verdict INSUFFICIENT")
        if self.abstain and not self.abstention_reason:
            raise ValueError("an abstaining output must provide abstention_reason")
        if not any(claim.claim_type == ClaimType.DECISION for claim in self.claims):
            raise ValueError("at least one decision claim is required")
        return self


_LEGACY_CONFIDENCE = {
    "HIGH": 0.90,
    "MEDIUM": 0.60,
    "LOW": 0.30,
}


def legacy_to_atomic(
    legacy: dict[str, Any],
    case_id: str,
) -> InvestigationOutput:
    """Convert a v1 response into the v2 structure without adding evidence.

    This adapter is for pilot auditing and regression tests.  A legacy chain
    description may contain several propositions, so it is conservatively typed
    as a hypothesis rather than pretending to be an atomic observation.
    """

    raw_confidence = str(legacy.get("confidence", "LOW")).upper()
    confidence = _LEGACY_CONFIDENCE.get(raw_confidence, 0.30)
    verdict_raw = str(legacy.get("verdict", "INSUFFICIENT")).upper()
    verdict = Verdict(verdict_raw) if verdict_raw in Verdict._value2member_map_ else Verdict.INSUFFICIENT

    claims: list[AtomicClaim] = []
    chain_citations: list[str] = []
    for index, step in enumerate(legacy.get("attack_chain", []) or [], start=1):
        event_id = step.get("event_id")
        citations = [str(event_id)] if event_id else []
        chain_citations.extend(citations)
        step_confidence = _LEGACY_CONFIDENCE.get(
            str(step.get("confidence", raw_confidence)).upper(),
            confidence,
        )
        claims.append(AtomicClaim(
            claim_id=f"legacy_chain_{index}",
            claim_type=ClaimType.HYPOTHESIS,
            subject=legacy.get("suspect"),
            predicate="legacy_attack_chain_step",
            object=str(step.get("description", "")) or None,
            modality=Modality.PROBABLE,
            cited_event_ids=citations,
            evidence_relation=(
                EvidenceRelation.SUPPORTS if citations else EvidenceRelation.INSUFFICIENT
            ),
            confidence=step_confidence,
            decisive=True,
            rationale="Converted from a non-atomic v1 attack-chain description.",
        ))

    evidence_for = [str(item) for item in legacy.get("evidence_for", []) if isinstance(item, str)]
    evidence_against = [
        str(item) for item in legacy.get("evidence_against", []) if isinstance(item, str)
    ]
    decision_citations = list(dict.fromkeys(evidence_for + chain_citations))
    claims.append(AtomicClaim(
        claim_id="legacy_decision",
        claim_type=ClaimType.DECISION,
        subject=legacy.get("suspect"),
        predicate=f"verdict_{verdict.value.lower()}",
        object="security_incident",
        modality=(
            Modality.PROBABLE if verdict != Verdict.INSUFFICIENT else Modality.UNKNOWN
        ),
        cited_event_ids=decision_citations,
        evidence_relation=(
            EvidenceRelation.SUPPORTS if decision_citations else EvidenceRelation.INSUFFICIENT
        ),
        confidence=confidence,
        decisive=True,
        rationale="Converted from the v1 verdict; semantic warrant is not implied.",
    ))

    alternatives: list[AlternativeHypothesis] = []
    for gap in legacy.get("gaps", []) or []:
        if isinstance(gap, str) and gap.strip():
            alternatives.append(AlternativeHypothesis(
                hypothesis=f"Unresolved gap: {gap.strip()}",
                cited_event_ids=[],
                confidence=0.25,
            ))

    return InvestigationOutput(
        case_id=case_id,
        verdict=verdict,
        suspect=legacy.get("suspect"),
        claims=claims,
        evidence_for=list(dict.fromkeys(evidence_for)),
        evidence_against=list(dict.fromkeys(evidence_against)),
        missing_evidence=[str(item) for item in legacy.get("gaps", []) if isinstance(item, str)],
        alternative_hypotheses=alternatives,
        overall_confidence=confidence,
        abstain=verdict == Verdict.INSUFFICIENT,
        abstention_reason=(
            str(legacy.get("confidence_explanation", "Legacy output was insufficient."))
            if verdict == Verdict.INSUFFICIENT
            else None
        ),
    )

