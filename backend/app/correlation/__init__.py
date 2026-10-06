"""Deterministic security-event correlation engine (Phase 1)."""

from .config import CorrelationConfig
from .engine import compute_investigation_id, correlate
from .models import (
    CorrelationLink,
    EventType,
    Investigation,
    NormalizedEvent,
    Strength,
)
from .normalization import (
    NormalizationError,
    load_events_from_scenario,
    normalize_event,
)

__all__ = [
    "CorrelationConfig",
    "CorrelationLink",
    "EventType",
    "Investigation",
    "NormalizationError",
    "NormalizedEvent",
    "Strength",
    "compute_investigation_id",
    "correlate",
    "load_events_from_scenario",
    "normalize_event",
]
