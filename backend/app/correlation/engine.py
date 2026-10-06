"""Deterministic correlation engine (Phase 1).

Pure, in-memory, standard-library only.  No clock reads, no randomness, no I/O,
no AI.  Given the same events and configuration the output is identical
regardless of input order.

Rules (all windows/caps are lab defaults from ``CorrelationConfig``):

* C1  local_account_created -> sudo_group_addition      STRONG   (merges)
* C2  failed_ssh_authentication -> local_account_created MODERATE (merges)
* C3  same event type recurrence, discriminating account STRONG   (merges)
* C4  same usable source IP across failed SSH events     MODERATE (never merges)

Safeguards: host alone or time alone never correlates; ``None`` never equals
``None``; C4 is preserved as evidence but never bridges investigations; nothing
is inferred about actors, authentication success, causation or MITRE.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

from .config import CorrelationConfig
from .models import (
    ENTITY_ACCOUNT,
    ENTITY_EVENT_TYPE,
    ENTITY_HOST,
    ENTITY_SOURCE_IP,
    CorrelationLink,
    CorrelationWarning,
    EntityRef,
    EventType,
    EvidenceGap,
    Investigation,
    NormalizedEvent,
    RelatedContextLink,
    Strength,
    TimelineEntry,
)

RULE_ORDER = ("C1", "C2", "C3", "C4")
MERGING_RULES = frozenset({"C1", "C2", "C3"})

_STRENGTH = {
    "C1": Strength.STRONG,
    "C2": Strength.MODERATE,
    "C3": Strength.STRONG,
    "C4": Strength.MODERATE,
}

_BASE_LIMITATION = (
    "Records shared entities, event ordering and time proximity only. "
    "It does not establish causation, attribution of any source to an action, "
    "successful access, or compromise. Analyst review is required."
)
_LIMITATIONS = {
    "C1": _BASE_LIMITATION
    + " Creation followed by a sudo-group addition for the same account does not "
    "show who performed either action or whether either was unauthorized.",
    "C2": _BASE_LIMITATION
    + " A failed SSH attempt preceding an account creation does not show that the "
    "SSH source created the account or gained access.",
    "C3": _BASE_LIMITATION
    + " Recurrence of the same event type does not by itself indicate intent.",
    "C4": _BASE_LIMITATION
    + " A shared source IP does not show that the same actor performed any other "
    "observed action.",
}

_UTC_MIN = datetime.min.replace(tzinfo=timezone.utc)

_SSH = EventType.FAILED_SSH_AUTHENTICATION
_CREATED = EventType.LOCAL_ACCOUNT_CREATED
_SUDO = EventType.SUDO_GROUP_ADDITION


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
def _chrono_key(event: NormalizedEvent) -> tuple:
    """Deterministic chronological order; events without a timestamp sort last."""
    return (event.timestamp is None, event.timestamp or _UTC_MIN, event.event_id)


def _q(value: str | None) -> str:
    return f"'{value}'" if value is not None else "unknown"


def _same_known(a: str | None, b: str | None) -> bool:
    """Equality that fails closed: None never equals None."""
    return a is not None and b is not None and a == b


def _is_generic(account: str, config: CorrelationConfig) -> bool:
    return account.strip().lower() in config.generic_accounts


def _ip_unusable_reason(ip: str, config: CorrelationConfig) -> str | None:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "UNUSABLE_ADDRESS"
    if (
        address.is_unspecified
        or address.is_loopback
        or address.is_multicast
        or address.is_link_local
    ):
        return "UNUSABLE_ADDRESS"
    if ip in config.infrastructure_ips:
        return "INFRASTRUCTURE_IP_CONFIGURED"
    return None


def compute_investigation_id(event_ids: Iterable[str]) -> str:
    """ID derived only from the sorted member event IDs.

    SHA-256 over the canonical JSON list of the lexically sorted IDs, truncated
    to 12 hex characters.  The ID changes whenever membership changes; stability
    across incremental ingestion is not a Phase 1 requirement.
    """
    canonical = json.dumps(sorted(event_ids), separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return "INV-" + digest[:12].upper()


# --------------------------------------------------------------------------
# Rules.  Each takes (earlier, later) in chronological order and returns a
# link or None.  Every rule checks required fields first (fail closed).
# --------------------------------------------------------------------------
def _make_link(
    rule_id: str,
    earlier: NormalizedEvent,
    later: NormalizedEvent,
    shared: tuple[tuple[str, str], ...],
    reason: str,
) -> CorrelationLink:
    return CorrelationLink(
        link_id=f"{rule_id}:{earlier.event_id}->{later.event_id}",
        rule_id=rule_id,
        strength=_STRENGTH[rule_id],
        earlier_event_id=earlier.event_id,
        later_event_id=later.event_id,
        earlier_timestamp=earlier.timestamp,
        later_timestamp=later.timestamp,
        time_difference=later.timestamp - earlier.timestamp,
        shared_entities=shared,
        merges_investigation=rule_id in MERGING_RULES,
        reason=reason,
        limitations=_LIMITATIONS[rule_id],
    )


def _ordered_identity_match(
    earlier: NormalizedEvent,
    later: NormalizedEvent,
    first_type: EventType,
    second_type: EventType,
    window: timedelta,
) -> bool:
    """Shared by C1/C2: types, same account+host, strict order, window.

    No generic-account exclusion here (by design); only C3 applies that.
    """
    if earlier.event_type is not first_type or later.event_type is not second_type:
        return False
    if earlier.timestamp is None or later.timestamp is None:
        return False
    if not earlier.timestamp < later.timestamp:  # strict; equal fails closed
        return False
    if not _same_known(earlier.host, later.host):
        return False
    if not _same_known(earlier.target_account, later.target_account):
        return False
    return later.timestamp - earlier.timestamp <= window


def _rule_c1(earlier, later, config):
    if not _ordered_identity_match(earlier, later, _CREATED, _SUDO, config.c1_window):
        return None
    delta = later.timestamp - earlier.timestamp
    reason = (
        f"Local account {_q(earlier.target_account)} was created and later added to "
        f"the local sudo group on host {_q(earlier.host)} ({delta} later). "
        "Same account identity and host; creation precedes the sudo-group addition."
    )
    shared = (
        (ENTITY_ACCOUNT, earlier.target_account),
        (ENTITY_HOST, earlier.host),
    )
    return _make_link("C1", earlier, later, shared, reason)


def _rule_c2(earlier, later, config):
    if not _ordered_identity_match(earlier, later, _SSH, _CREATED, config.c2_window):
        return None
    delta = later.timestamp - earlier.timestamp
    reason = (
        f"Failed SSH authentication for account {_q(earlier.target_account)} on host "
        f"{_q(earlier.host)} preceded creation of local account "
        f"{_q(later.target_account)} ({delta} later). "
        "Same account identity and host, correct order, within the configured window."
    )
    shared = (
        (ENTITY_ACCOUNT, earlier.target_account),
        (ENTITY_HOST, earlier.host),
    )
    return _make_link("C2", earlier, later, shared, reason)


def _rule_c3(earlier, later, config):
    if earlier.event_type is EventType.UNKNOWN or earlier.event_type is not later.event_type:
        return None
    if earlier.timestamp is None or later.timestamp is None:
        return None
    if not _same_known(earlier.target_account, later.target_account):
        return None
    if _is_generic(earlier.target_account, config):
        return None  # generic account cannot be the sole discriminating identity
    if not _same_known(earlier.host, later.host):
        return None
    delta = later.timestamp - earlier.timestamp
    if delta > config.c3_window:
        return None
    reason = (
        f"Two {earlier.event_type.value} events for account "
        f"{_q(earlier.target_account)} on host {_q(earlier.host)} occurred "
        f"{delta} apart."
    )
    shared = (
        (ENTITY_EVENT_TYPE, earlier.event_type.value),
        (ENTITY_ACCOUNT, earlier.target_account),
        (ENTITY_HOST, earlier.host),
    )
    return _make_link("C3", earlier, later, shared, reason)


def _rule_c4(earlier, later, config):
    if earlier.event_type is not _SSH or later.event_type is not _SSH:
        return None
    if earlier.timestamp is None or later.timestamp is None:
        return None
    if not _same_known(earlier.source_ip, later.source_ip):
        return None
    if _ip_unusable_reason(earlier.source_ip, config) is not None:
        return None
    delta = later.timestamp - earlier.timestamp
    if delta > config.c4_window:
        return None
    reason = (
        f"Failed SSH authentication events share source IP {earlier.source_ip} and "
        f"occurred {delta} apart (accounts {_q(earlier.target_account)} and "
        f"{_q(later.target_account)}). Preserved as evidence; not used to merge "
        "investigations."
    )
    shared = ((ENTITY_SOURCE_IP, earlier.source_ip),)
    return _make_link("C4", earlier, later, shared, reason)


_RULES = (_rule_c1, _rule_c2, _rule_c3, _rule_c4)


def _find_links(
    ordered: list[NormalizedEvent], config: CorrelationConfig
) -> list[CorrelationLink]:
    links: list[CorrelationLink] = []
    for i, earlier in enumerate(ordered):
        for later in ordered[i + 1:]:
            for rule in _RULES:
                link = rule(earlier, later, config)
                if link is not None:
                    links.append(link)
    return links


# --------------------------------------------------------------------------
# Clustering (union-find over merging links only, with size/span caps)
# --------------------------------------------------------------------------
class _Clusters:
    def __init__(self, events: list[NormalizedEvent]) -> None:
        self._parent = {e.event_id: e.event_id for e in events}
        self._size = {e.event_id: 1 for e in events}
        self._first = {e.event_id: e.timestamp for e in events}
        self._last = {e.event_id: e.timestamp for e in events}

    def find(self, event_id: str) -> str:
        root = event_id
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[event_id] != root:  # path compression
            self._parent[event_id], event_id = root, self._parent[event_id]
        return root

    def try_union(self, a: str, b: str, config: CorrelationConfig) -> tuple[str, ...]:
        """Merge the clusters of a and b unless a cap would be exceeded.

        Returns the violated cap codes (empty tuple means merged / already one).
        """
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ()

        violations = []
        if self._size[ra] + self._size[rb] > config.max_investigation_events:
            violations.append("SIZE_CAP")

        stamps = [t for t in (self._first[ra], self._first[rb]) if t is not None]
        ends = [t for t in (self._last[ra], self._last[rb]) if t is not None]
        first = min(stamps) if stamps else None
        last = max(ends) if ends else None
        if first is not None and last is not None:
            if last - first > config.max_investigation_span:
                violations.append("SPAN_CAP")

        if violations:
            return tuple(violations)

        root, child = (ra, rb) if ra < rb else (rb, ra)
        self._parent[child] = root
        self._size[root] += self._size[child]
        self._first[root] = first
        self._last[root] = last
        return ()


_CAP_TEXT = {
    "SIZE_CAP": "maximum investigation size",
    "SPAN_CAP": "maximum investigation time span",
}


# --------------------------------------------------------------------------
# Investigation assembly
# --------------------------------------------------------------------------
def _summary(event: NormalizedEvent) -> str:
    account, host = _q(event.target_account), _q(event.host)
    if event.event_type is _SSH:
        return (
            f"Failed SSH authentication for account {account} on host {host} "
            f"from source IP {event.source_ip or 'unknown'}."
        )
    if event.event_type is _CREATED:
        return f"Local account {account} created on host {host}."
    if event.event_type is _SUDO:
        return f"Account {account} added to the local sudo group on host {host}."
    return (
        f"Event of unrecognized type {_q(event.raw_event_type)} observed on host {host}."
    )


def _timeline_entry(event: NormalizedEvent) -> TimelineEntry:
    return TimelineEntry(
        timestamp=event.timestamp,
        event_id=event.event_id,
        event_type=event.event_type,
        host=event.host,
        target_account=event.target_account,
        source_ip=event.source_ip,
        summary=_summary(event),
    )


def _link_sort_key(link: CorrelationLink) -> tuple:
    return (
        RULE_ORDER.index(link.rule_id),
        link.earlier_timestamp,
        link.earlier_event_id,
        link.later_event_id,
    )


def correlate(
    events: Iterable[NormalizedEvent],
    config: CorrelationConfig | None = None,
) -> list[Investigation]:
    """Correlate events into investigations.

    Every event belongs to exactly one investigation (singletons included).
    Raises ``ValueError`` on duplicate event IDs.
    """
    config = config or CorrelationConfig()
    event_list = list(events)

    ids = [e.event_id for e in event_list]
    if len(set(ids)) != len(ids):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError(f"duplicate event_id values: {duplicates}")

    ordered = sorted(event_list, key=_chrono_key)
    by_id = {e.event_id: e for e in ordered}
    links = _find_links(ordered, config)

    # Cluster using merging links only; strongest first, then chronological.
    clusters = _Clusters(ordered)
    merging = sorted(
        (l for l in links if l.merges_investigation),
        key=lambda l: (
            -l.strength.value,
            l.earlier_timestamp,
            l.earlier_event_id,
            l.later_event_id,
            l.rule_id,
        ),
    )
    rejected: list[tuple[CorrelationLink, tuple[str, ...]]] = []
    for link in merging:
        violated = clusters.try_union(link.earlier_event_id, link.later_event_id, config)
        if violated:
            rejected.append((link, violated))

    # Group events into clusters.
    members: dict[str, list[NormalizedEvent]] = {}
    for event in ordered:  # already chronological
        members.setdefault(clusters.find(event.event_id), []).append(event)

    investigation_ids = {
        root: compute_investigation_id(e.event_id for e in evs)
        for root, evs in members.items()
    }
    if len(set(investigation_ids.values())) != len(investigation_ids):
        raise ValueError("investigation ID collision")  # practically unreachable
    root_of = {e.event_id: clusters.find(e.event_id) for e in ordered}

    # Cap warnings are kept only if the link's endpoints really ended up apart.
    warnings_by_root: dict[str, list[CorrelationWarning]] = {r: [] for r in members}
    for link, codes in rejected:
        ra, rb = root_of[link.earlier_event_id], root_of[link.later_event_id]
        if ra == rb:
            continue
        for code in codes:
            warning = CorrelationWarning(
                code=code,
                message=(
                    f"Link {link.link_id} ({link.rule_id}) was not applied because "
                    f"merging would exceed the configured {_CAP_TEXT[code]}."
                ),
                link_id=link.link_id,
                event_ids=(link.earlier_event_id, link.later_event_id),
            )
            warnings_by_root[ra].append(warning)
            warnings_by_root[rb].append(warning)

    investigations: list[Investigation] = []
    for root, evs in members.items():
        inv_id = investigation_ids[root]
        member_ids = {e.event_id for e in evs}

        inside = sorted(
            (l for l in links
             if l.earlier_event_id in member_ids and l.later_event_id in member_ids),
            key=_link_sort_key,
        )

        context: list[RelatedContextLink] = []
        for link in sorted(links, key=_link_sort_key):
            ends = (
                (link.earlier_event_id, link.later_event_id),
                (link.later_event_id, link.earlier_event_id),
            )
            for here, there in ends:
                if here in member_ids and root_of[there] != root:
                    context.append(
                        RelatedContextLink(
                            link=link,
                            this_event_id=here,
                            other_investigation_id=investigation_ids[root_of[there]],
                            other_event_id=there,
                        )
                    )

        accounts = sorted({e.target_account for e in evs if e.target_account})
        hosts = sorted({e.host for e in evs if e.host})
        ips = sorted({e.source_ip for e in evs if e.source_ip})

        account_refs = tuple(
            EntityRef(
                ENTITY_ACCOUNT, a,
                pivot_eligible=not _is_generic(a, config),
                reason="GENERIC_ACCOUNT" if _is_generic(a, config) else None,
            )
            for a in accounts
        )
        host_refs = tuple(
            EntityRef(ENTITY_HOST, h, pivot_eligible=False,
                      reason="HOST_ALONE_NEVER_CORRELATES")
            for h in hosts
        )
        ip_refs = tuple(
            EntityRef(
                ENTITY_SOURCE_IP, ip,
                pivot_eligible=_ip_unusable_reason(ip, config) is None,
                reason=_ip_unusable_reason(ip, config),
            )
            for ip in ips
        )

        techniques: dict[str, list[str]] = {}
        for e in evs:
            if e.mitre_technique:
                techniques.setdefault(e.mitre_technique, []).append(e.event_id)
        mitre = tuple(
            (t, tuple(ids_)) for t, ids_ in sorted(techniques.items())
        )

        gaps: tuple[tuple[str, EvidenceGap], ...] = tuple(
            (e.event_id, gap) for e in evs for gap in e.evidence_gaps
        )

        investigations.append(
            Investigation(
                investigation_id=inv_id,
                event_ids=tuple(e.event_id for e in evs),
                timeline=tuple(_timeline_entry(by_id[e.event_id]) for e in evs),
                links=tuple(inside),
                related_context_links=tuple(context),
                accounts=account_refs,
                hosts=host_refs,
                source_ips=ip_refs,
                mitre_techniques=mitre,
                evidence_gaps=gaps,
                warnings=tuple(warnings_by_root[root]),
            )
        )

    investigations.sort(key=lambda inv: _chrono_key(by_id[inv.event_ids[0]]))
    return investigations
