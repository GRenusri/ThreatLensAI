"""Data structures for the deterministic correlation engine (Phase 1).

Everything here is an immutable dataclass.  Unknown values are represented as
``None`` plus an explicit ``EvidenceGap``; they are never inferred or defaulted.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

# Entity kinds used in ``shared_entities`` and ``EntityRef``.
ENTITY_ACCOUNT = "account"
ENTITY_HOST = "host"
ENTITY_SOURCE_IP = "source_ip"
ENTITY_EVENT_TYPE = "event_type"

# Telemetry that the current detections do not collect.  It is listed on every
# investigation so that downstream consumers never mistake "unknown" for "none".
UNAVAILABLE_TELEMETRY = ("actor_user", "session_id")


class EventType(str, Enum):
    FAILED_SSH_AUTHENTICATION = "failed_ssh_authentication"
    LOCAL_ACCOUNT_CREATED = "local_account_created"
    SUDO_GROUP_ADDITION = "sudo_group_addition"
    UNKNOWN = "unknown"


class Strength(Enum):
    """Correlation strength label.  This is a label, not a probability."""

    MODERATE = 2
    STRONG = 3


class GapReason(str, Enum):
    ABSENT_IN_EVIDENCE = "absent_in_evidence"
    UNPARSEABLE_VALUE = "unparseable_value"
    TIMEZONE_MISSING = "timezone_missing"
    UNRECOGNIZED_VALUE = "unrecognized_value"


@dataclass(frozen=True)
class EvidenceGap:
    """A field that is unknown for an event, and why."""

    field_name: str
    reason: GapReason


@dataclass(frozen=True)
class NormalizedEvent:
    """One alert/detection-level event in the engine's canonical form."""

    event_id: str
    event_type: EventType
    raw_event_type: str | None = None
    timestamp: datetime | None = None  # timezone-aware, UTC
    host: str | None = None
    target_account: str | None = None
    source_ip: str | None = None  # canonical IP text; None if absent/invalid
    origin: str | None = None  # raw "source" of useradd (a tty path); never an IP
    process_name: str | None = None
    authentication_result: str | None = None
    account_state_at_event: str | None = None
    uid: int | None = None
    gid: int | None = None
    home_directory: str | None = None
    shell: str | None = None
    mitre_technique: str | None = None  # only if supplied by the evidence
    evidence_gaps: tuple[EvidenceGap, ...] = ()


@dataclass(frozen=True)
class CorrelationLink:
    """Explainable pairwise relationship between two events."""

    link_id: str
    rule_id: str
    strength: Strength
    earlier_event_id: str
    later_event_id: str
    earlier_timestamp: datetime
    later_timestamp: datetime
    time_difference: timedelta
    shared_entities: tuple[tuple[str, str], ...]
    merges_investigation: bool
    reason: str
    limitations: str


@dataclass(frozen=True)
class TimelineEntry:
    timestamp: datetime | None
    event_id: str
    event_type: EventType
    host: str | None
    target_account: str | None
    source_ip: str | None
    summary: str


@dataclass(frozen=True)
class EntityRef:
    """An entity seen in an investigation.

    ``pivot_eligible`` says whether the entity may drive automatic correlation
    under the rules that apply a discriminating-entity test (accounts for C3,
    source IPs for C4).  Entities that are not eligible are still preserved.
    """

    kind: str
    value: str
    pivot_eligible: bool
    reason: str | None = None


@dataclass(frozen=True)
class RelatedContextLink:
    """A link whose endpoints are in different investigations (not merged)."""

    link: CorrelationLink
    this_event_id: str
    other_investigation_id: str
    other_event_id: str


@dataclass(frozen=True)
class CorrelationWarning:
    code: str
    message: str
    link_id: str
    event_ids: tuple[str, ...]


@dataclass(frozen=True)
class Investigation:
    investigation_id: str
    event_ids: tuple[str, ...]  # chronological
    timeline: tuple[TimelineEntry, ...]
    links: tuple[CorrelationLink, ...]
    related_context_links: tuple[RelatedContextLink, ...]
    accounts: tuple[EntityRef, ...]
    hosts: tuple[EntityRef, ...]
    source_ips: tuple[EntityRef, ...]
    mitre_techniques: tuple[tuple[str, tuple[str, ...]], ...]
    evidence_gaps: tuple[tuple[str, EvidenceGap], ...]
    warnings: tuple[CorrelationWarning, ...]

    @property
    def unavailable_telemetry(self) -> tuple[str, ...]:
        return UNAVAILABLE_TELEMETRY

    @property
    def analyst_review_required(self) -> bool:
        """Always True.  Human review is mandatory and not configurable."""
        return True
