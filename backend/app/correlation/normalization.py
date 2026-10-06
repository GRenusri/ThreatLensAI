"""Convert raw evidence dictionaries into ``NormalizedEvent`` objects.

Principles: fail closed, never infer.  A value that is absent, blank, invalid
or ambiguous becomes ``None`` and (where relevant) an ``EvidenceGap``.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from datetime import datetime, timezone

from .models import EventType, EvidenceGap, GapReason, NormalizedEvent


class NormalizationError(ValueError):
    """Raised when evidence cannot be accepted at all (e.g. no event_id)."""


_EVENT_TYPE_BY_VALUE = {
    member.value: member for member in EventType if member is not EventType.UNKNOWN
}

# Fields every event is expected to carry, plus the extra field SSH events need.
_EXPECTED_FIELDS = ("timestamp", "host", "target_account")

# A fractional-second part that follows ":SS".
_FRACTION_RE = re.compile(r"(?<=:\d\d)\.(\d+)")


def _is_absent(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


def clean_text(value: object) -> str | None:
    """Strip whitespace; return None for non-strings and blank strings."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def parse_timestamp(value: object) -> tuple[datetime | None, GapReason | None]:
    """Parse a timezone-aware ISO-8601 timestamp and normalise it to UTC.

    Accepts ``Z``/``z`` or a numeric UTC offset and any fractional-second
    precision (digits beyond microseconds are truncated, as ``datetime`` cannot
    hold them).  Naive or unparseable values return ``(None, reason)``; no
    timezone is ever assumed.
    """
    if _is_absent(value):
        return None, GapReason.ABSENT_IN_EVIDENCE
    if not isinstance(value, str):
        return None, GapReason.UNPARSEABLE_VALUE

    text = value.strip()
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None, GapReason.UNPARSEABLE_VALUE

    if parsed.tzinfo is None or parsed.tzinfo.utcoffset(parsed) is None:
        return None, GapReason.TIMEZONE_MISSING
    return parsed.astimezone(timezone.utc), None


def parse_ip(value: object) -> tuple[str | None, GapReason | None]:
    """Return the canonical text form of an IP address, or ``(None, reason)``."""
    if _is_absent(value):
        return None, GapReason.ABSENT_IN_EVIDENCE
    if not isinstance(value, str):
        return None, GapReason.UNPARSEABLE_VALUE
    try:
        return str(ipaddress.ip_address(value.strip())), None
    except ValueError:
        return None, GapReason.UNPARSEABLE_VALUE


def _text_with_reason(value: object) -> tuple[str | None, GapReason | None]:
    if _is_absent(value):
        return None, GapReason.ABSENT_IN_EVIDENCE
    text = clean_text(value)
    if text is None:
        return None, GapReason.UNPARSEABLE_VALUE
    return text, None


def _to_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def normalize_event(raw: Mapping) -> NormalizedEvent:
    """Normalise one raw evidence event."""
    if not isinstance(raw, Mapping):
        raise NormalizationError("event must be a mapping")

    raw_id = raw.get("event_id")
    if not isinstance(raw_id, str) or not raw_id.strip():
        raise NormalizationError("event_id is required and must be a non-blank string")
    event_id = raw_id.strip()

    gaps: list[EvidenceGap] = []

    # Event type.
    raw_type = clean_text(raw.get("event_type"))
    event_type = _EVENT_TYPE_BY_VALUE.get(raw_type) if raw_type else None
    if event_type is None:
        event_type = EventType.UNKNOWN
        gaps.append(
            EvidenceGap(
                "event_type",
                GapReason.ABSENT_IN_EVIDENCE if raw_type is None
                else GapReason.UNRECOGNIZED_VALUE,
            )
        )

    expected = set(_EXPECTED_FIELDS)
    if event_type is EventType.FAILED_SSH_AUTHENTICATION:
        expected.add("source_ip")

    def record(name: str, value: object, reason: GapReason | None) -> None:
        """Record a gap if the value is unknown and expected (or present but bad)."""
        if value is not None:
            return
        if reason is GapReason.ABSENT_IN_EVIDENCE and name not in expected:
            return
        if reason is not None:
            gaps.append(EvidenceGap(name, reason))

    timestamp, reason = parse_timestamp(raw.get("timestamp"))
    record("timestamp", timestamp, reason)

    host, reason = _text_with_reason(raw.get("host"))
    record("host", host, reason)

    account, reason = _text_with_reason(raw.get("target_account"))
    record("target_account", account, reason)

    source_ip, reason = parse_ip(raw.get("source_ip"))
    record("source_ip", source_ip, reason)

    return NormalizedEvent(
        event_id=event_id,
        event_type=event_type,
        raw_event_type=raw_type,
        timestamp=timestamp,
        host=host,
        target_account=account,
        source_ip=source_ip,
        origin=clean_text(raw.get("source")),
        process_name=clean_text(raw.get("process_name")),
        authentication_result=clean_text(raw.get("authentication_result")),
        account_state_at_event=clean_text(raw.get("account_state_at_event")),
        uid=_to_int(raw.get("uid")),
        gid=_to_int(raw.get("gid")),
        home_directory=clean_text(raw.get("home_directory")),
        shell=clean_text(raw.get("shell")),
        mitre_technique=clean_text(raw.get("mitre_technique")),
        evidence_gaps=tuple(gaps),
    )


def load_events_from_scenario(data: Mapping) -> list[NormalizedEvent]:
    """Normalise the ``events`` list of a scenario document.

    Only ``events`` is read.  Scenario-level labels (``host``,
    ``primary_account``, ``decoy_account``, ``authorized_test``...) are ignored
    on purpose: they are ground truth for tests, not evidence, and a missing
    per-event host must never be back-filled from them.
    """
    if not isinstance(data, Mapping) or not isinstance(data.get("events"), list):
        raise NormalizationError("scenario must contain an 'events' list")
    return [normalize_event(raw) for raw in data["events"]]
