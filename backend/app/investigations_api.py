"""Investigation API (Phase 2).

A read-only HTTP view of the deterministic Phase 1 correlation output for the
controlled lab scenario.  This module is the only place that knows about HTTP:
the correlation package stays independent of FastAPI/Pydantic.

Pipeline (executed on every request; no caching, no state):

    correlation_lab_scenario.json
      -> load_events_from_scenario()
      -> correlate()
      -> Investigation objects (Phase 1 dataclasses, never returned directly)
      -> explicit DTO serializers
      -> GET /investigations, GET /investigations/{investigation_id}

The evidence is controlled portfolio/lab data.  It is NOT live Sentinel
ingestion, and nothing here creates new security conclusions: reason,
limitations and timeline summaries are the engine's own text, passed through
unchanged.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from backend.app.correlation import (
    CorrelationLink,
    Investigation,
    NormalizationError,
    correlate,
    load_events_from_scenario,
)

logger = logging.getLogger(__name__)

# Resolved from this module's location (backend/app/ -> backend/data/), never
# from the process working directory.
SCENARIO_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "correlation_lab_scenario.json"
)

router = APIRouter(prefix="/investigations", tags=["investigations"])


# --------------------------------------------------------------------------
# Response DTOs (explicit API contract; field order is the output order)
# --------------------------------------------------------------------------
class _Dto(BaseModel):
    model_config = ConfigDict(frozen=True)


class EvidenceSource(_Dto):
    """Provenance label.  Static: it does not read scenario-level labels."""

    type: Literal["controlled_lab_scenario"]
    scenario_file: str
    live_sentinel_ingestion: Literal[False]


class SharedEntity(_Dto):
    kind: str
    value: str


class CorrelationLinkDto(_Dto):
    link_id: str
    rule_id: str
    strength: Literal["MODERATE", "STRONG"]
    earlier_event_id: str
    later_event_id: str
    earlier_timestamp: str
    later_timestamp: str
    time_difference_ms: int
    shared_entities: list[SharedEntity]
    merges_investigation: bool
    reason: str
    limitations: str


class TimelineEntryDto(_Dto):
    timestamp: Optional[str]
    event_id: str
    event_type: str
    host: Optional[str]
    target_account: Optional[str]
    source_ip: Optional[str]
    summary: str


class RelatedContextLinkDto(_Dto):
    """A link whose endpoints are in different investigations.

    Nothing was merged.  ``merge_outcome`` explains why, using the link's own
    ``merges_investigation`` flag and the engine's warnings:

    * ``not_merged_by_design``  - the rule never merges (C4).
    * ``not_merged_cap_limited`` - the rule normally merges, but the engine
      reported a size/span cap warning for this exact link.
    * ``not_merged_unexplained`` - a merging rule stayed cross-investigation
      with no matching engine warning (should not occur; surfaced, not hidden).
    """

    this_event_id: str
    other_investigation_id: str
    other_event_id: str
    merge_outcome: Literal[
        "not_merged_by_design", "not_merged_cap_limited", "not_merged_unexplained"
    ]
    link: CorrelationLinkDto


class EntityRefDto(_Dto):
    kind: str
    value: str
    pivot_eligible: bool
    reason: Optional[str]


class MitreTechniqueDto(_Dto):
    technique: str
    event_ids: list[str]


class EvidenceGapDto(_Dto):
    event_id: str
    field_name: str
    reason: str


class WarningDto(_Dto):
    code: str
    message: str
    link_id: str
    event_ids: list[str]


class InvestigationSummary(_Dto):
    investigation_id: str
    event_ids: list[str]
    event_count: int
    first_event_timestamp: Optional[str]
    last_event_timestamp: Optional[str]
    accounts: list[str]
    hosts: list[str]
    source_ips: list[str]
    rule_ids: list[str]
    related_context_link_count: int
    warning_count: int
    evidence_gap_count: int
    analyst_review_required: bool


class InvestigationDetail(_Dto):
    investigation_id: str
    evidence_source: EvidenceSource
    event_ids: list[str]
    event_count: int
    timeline: list[TimelineEntryDto]
    links: list[CorrelationLinkDto]
    related_context_links: list[RelatedContextLinkDto]
    accounts: list[EntityRefDto]
    hosts: list[EntityRefDto]
    source_ips: list[EntityRefDto]
    mitre_techniques: list[MitreTechniqueDto]
    evidence_gaps: list[EvidenceGapDto]
    warnings: list[WarningDto]
    unavailable_telemetry: list[str]
    analyst_review_required: bool


class InvestigationListResponse(_Dto):
    count: int
    evidence_source: EvidenceSource
    investigations: list[InvestigationSummary]


EVIDENCE_SOURCE = EvidenceSource(
    type="controlled_lab_scenario",
    scenario_file=SCENARIO_PATH.name,
    live_sentinel_ingestion=False,
)


# --------------------------------------------------------------------------
# Serialization boundary: Phase 1 dataclasses -> DTOs
# --------------------------------------------------------------------------
def to_utc_iso(moment: Optional[datetime]) -> Optional[str]:
    """Fixed-format UTC timestamp, e.g. ``2026-10-05T23:44:21.105000Z``.

    Always six fractional digits and a ``Z`` suffix, so strings are stable and
    sort lexically in chronological order.  ``None`` stays ``None`` (unknown).
    """
    if moment is None:
        return None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("naive datetime cannot be serialized")
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def to_millis(delta: timedelta) -> int:
    """Whole milliseconds (truncated; never overstates the difference)."""
    return delta // timedelta(milliseconds=1)


def serialize_link(link: CorrelationLink) -> CorrelationLinkDto:
    return CorrelationLinkDto(
        link_id=link.link_id,
        rule_id=link.rule_id,
        strength=link.strength.name,
        earlier_event_id=link.earlier_event_id,
        later_event_id=link.later_event_id,
        earlier_timestamp=to_utc_iso(link.earlier_timestamp),
        later_timestamp=to_utc_iso(link.later_timestamp),
        time_difference_ms=to_millis(link.time_difference),
        shared_entities=[SharedEntity(kind=k, value=v) for k, v in link.shared_entities],
        merges_investigation=link.merges_investigation,
        reason=link.reason,
        limitations=link.limitations,
    )


def _merge_outcome(link: CorrelationLink, investigation: Investigation) -> str:
    if not link.merges_investigation:
        return "not_merged_by_design"
    if any(w.link_id == link.link_id for w in investigation.warnings):
        return "not_merged_cap_limited"
    return "not_merged_unexplained"


def serialize_summary(investigation: Investigation) -> InvestigationSummary:
    stamps = [t.timestamp for t in investigation.timeline if t.timestamp is not None]
    return InvestigationSummary(
        investigation_id=investigation.investigation_id,
        event_ids=list(investigation.event_ids),
        event_count=len(investigation.event_ids),
        first_event_timestamp=to_utc_iso(min(stamps)) if stamps else None,
        last_event_timestamp=to_utc_iso(max(stamps)) if stamps else None,
        accounts=[a.value for a in investigation.accounts],
        hosts=[h.value for h in investigation.hosts],
        source_ips=[i.value for i in investigation.source_ips],
        rule_ids=sorted({link.rule_id for link in investigation.links}),
        related_context_link_count=len(investigation.related_context_links),
        warning_count=len(investigation.warnings),
        evidence_gap_count=len(investigation.evidence_gaps),
        analyst_review_required=investigation.analyst_review_required,
    )


def _entity(ref) -> EntityRefDto:
    return EntityRefDto(
        kind=ref.kind,
        value=ref.value,
        pivot_eligible=ref.pivot_eligible,
        reason=ref.reason,
    )


def serialize_detail(investigation: Investigation) -> InvestigationDetail:
    return InvestigationDetail(
        investigation_id=investigation.investigation_id,
        evidence_source=EVIDENCE_SOURCE,
        event_ids=list(investigation.event_ids),
        event_count=len(investigation.event_ids),
        timeline=[
            TimelineEntryDto(
                timestamp=to_utc_iso(t.timestamp),
                event_id=t.event_id,
                event_type=t.event_type.value,
                host=t.host,
                target_account=t.target_account,
                source_ip=t.source_ip,
                summary=t.summary,
            )
            for t in investigation.timeline
        ],
        links=[serialize_link(l) for l in investigation.links],
        related_context_links=[
            RelatedContextLinkDto(
                this_event_id=c.this_event_id,
                other_investigation_id=c.other_investigation_id,
                other_event_id=c.other_event_id,
                merge_outcome=_merge_outcome(c.link, investigation),
                link=serialize_link(c.link),
            )
            for c in investigation.related_context_links
        ],
        accounts=[_entity(r) for r in investigation.accounts],
        hosts=[_entity(r) for r in investigation.hosts],
        source_ips=[_entity(r) for r in investigation.source_ips],
        mitre_techniques=[
            MitreTechniqueDto(technique=t, event_ids=list(ids))
            for t, ids in investigation.mitre_techniques
        ],
        evidence_gaps=[
            EvidenceGapDto(
                event_id=event_id,
                field_name=gap.field_name,
                reason=gap.reason.value,
            )
            for event_id, gap in investigation.evidence_gaps
        ],
        warnings=[
            WarningDto(
                code=w.code,
                message=w.message,
                link_id=w.link_id,
                event_ids=list(w.event_ids),
            )
            for w in investigation.warnings
        ],
        unavailable_telemetry=list(investigation.unavailable_telemetry),
        analyst_review_required=investigation.analyst_review_required,
    )


# --------------------------------------------------------------------------
# Evidence loading (fail closed) and HTTP error mapping
# --------------------------------------------------------------------------
class EvidenceError(Exception):
    """Evidence cannot be trusted.  Carries a fixed code and a fixed message
    (never the raw evidence, an exception text, or a filesystem path)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(code)
        self.code = code
        self.message = message


def _load_investigations() -> list[Investigation]:
    """Load -> normalize -> correlate.  Runs on every request."""
    try:
        text = SCENARIO_PATH.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise EvidenceError(
            "EVIDENCE_MALFORMED", "The controlled scenario evidence is not valid JSON."
        ) from None
    except OSError:
        raise EvidenceError(
            "EVIDENCE_UNAVAILABLE",
            "The controlled scenario evidence file could not be read.",
        ) from None

    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        raise EvidenceError(
            "EVIDENCE_MALFORMED", "The controlled scenario evidence is not valid JSON."
        ) from None

    try:
        events = load_events_from_scenario(data)
    except NormalizationError:
        raise EvidenceError(
            "EVIDENCE_INVALID",
            "The controlled scenario evidence is structurally invalid.",
        ) from None

    if not events:
        raise EvidenceError(
            "EVIDENCE_EMPTY", "The controlled scenario evidence contains no events."
        )

    event_ids = [event.event_id for event in events]
    if len(set(event_ids)) != len(event_ids):
        raise EvidenceError(
            "EVIDENCE_DUPLICATE_EVENT_ID",
            "The controlled scenario evidence contains duplicate event IDs.",
        )

    return correlate(events)


def _run(build):
    """Run ``build()`` and map failures to deterministic HTTP errors."""
    try:
        return build()
    except HTTPException:
        raise
    except EvidenceError as error:
        raise HTTPException(
            status_code=503,
            detail={"code": error.code, "message": error.message},
        ) from None
    except Exception:
        # Details go to the server log only, never to the response.
        logger.error("Unexpected failure while building investigations", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "code": "INTERNAL_ERROR",
                "message": "An unexpected internal error occurred.",
            },
        ) from None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@router.get(
    "",
    response_model=InvestigationListResponse,
    summary="List deterministic investigations (controlled lab scenario)",
    description=(
        "Deterministic correlation output for the controlled lab scenario "
        "evidence file. This is not live Sentinel ingestion. Correlation links "
        "record shared entities, ordering and time proximity only; analyst "
        "review is always required."
    ),
    responses={
        503: {"description": "Scenario evidence missing, malformed, empty or invalid."},
        500: {"description": "Unexpected internal error."},
    },
)
def list_investigations():
    def build():
        summaries = [serialize_summary(inv) for inv in _load_investigations()]
        return InvestigationListResponse(
            count=len(summaries),
            evidence_source=EVIDENCE_SOURCE,
            investigations=summaries,
        )

    return _run(build)


@router.get(
    "/{investigation_id}",
    response_model=InvestigationDetail,
    summary="Get one deterministic investigation",
    description=(
        "Ordered timeline, correlation links with rule, strength, shared "
        "entities, reason and limitations, related-context links, entities, "
        "evidence gaps, warnings and unavailable telemetry. No conclusions are "
        "added beyond the engine's own output."
    ),
    responses={
        404: {"description": "No investigation with this ID."},
        503: {"description": "Scenario evidence missing, malformed, empty or invalid."},
        500: {"description": "Unexpected internal error."},
    },
)
def get_investigation(investigation_id: str):
    def build():
        for investigation in _load_investigations():
            if investigation.investigation_id == investigation_id:
                return serialize_detail(investigation)
        raise HTTPException(
            status_code=404,
            detail={
                "code": "INVESTIGATION_NOT_FOUND",
                "message": "No investigation with the requested ID exists.",
            },
        )

    return _run(build)
