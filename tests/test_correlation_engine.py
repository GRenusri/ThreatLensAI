"""Unit tests for the deterministic correlation engine (Phase 1).

Fixtures are small in-code events.  Times are expressed as offsets from BASE so
that window boundaries are exact.
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.correlation import (
    CorrelationConfig,
    NormalizationError,
    compute_investigation_id,
    correlate,
    load_events_from_scenario,
    normalize_event,
)
from backend.app.correlation.models import EventType, GapReason, Strength

BASE = datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)
HOST = "soc-linux-01"

SSH = "failed_ssh_authentication"
CREATED = "local_account_created"
SUDO = "sudo_group_addition"

FORBIDDEN_WORDS = ("attack", "compromise", "malicious", "caused", "breach")


def stamp(seconds=0, **kwargs):
    moment = BASE + timedelta(seconds=seconds, **kwargs)
    return moment.isoformat().replace("+00:00", "Z")


def raw(event_id, event_type, at=0, account="ctl-corr-user", host=HOST, ip=None,
        **extra):
    event = {"event_id": event_id, "event_type": event_type}
    if at is not None:
        event["timestamp"] = at if isinstance(at, str) else stamp(at)
    if host is not None:
        event["host"] = host
    if account is not None:
        event["target_account"] = account
    if ip is not None:
        event["source_ip"] = ip
    event.update(extra)
    return event


def run(*raws, config=None):
    return correlate([normalize_event(r) for r in raws], config)


def rule_ids(investigation):
    return sorted(link.rule_id for link in investigation.links)


def sizes(investigations):
    return sorted(len(i.event_ids) for i in investigations)


# ---------------------------------------------------------------- C1
def test_c1_links_creation_to_later_sudo_addition_as_strong():
    result = run(raw("a", CREATED, 0), raw("b", SUDO, 600))
    assert len(result) == 1
    (link,) = result[0].links
    assert link.rule_id == "C1"
    assert link.strength is Strength.STRONG
    assert link.time_difference == timedelta(minutes=10)
    assert link.merges_investigation is True


def test_c1_reversed_order_does_not_correlate():
    result = run(raw("a", SUDO, 0), raw("b", CREATED, 600))
    assert sizes(result) == [1, 1]
    assert all(not inv.links for inv in result)


def test_c1_equal_timestamps_fail_closed():
    result = run(raw("a", CREATED, 0), raw("b", SUDO, 0))
    assert sizes(result) == [1, 1]


def test_c1_window_boundary_is_inclusive():
    inside = run(raw("a", CREATED, 0), raw("b", SUDO, 24 * 3600))
    outside = run(raw("a", CREATED, 0), raw("b", SUDO, at=stamp(hours=24, milliseconds=1)))
    assert sizes(inside) == [2]
    assert sizes(outside) == [1, 1]


def test_c1_different_account_or_host_does_not_correlate():
    assert sizes(run(raw("a", CREATED, 0), raw("b", SUDO, 60, account="other"))) == [1, 1]
    assert sizes(run(raw("a", CREATED, 0), raw("b", SUDO, 60, host="other-host"))) == [1, 1]


def test_c1_missing_account_missing_host_missing_timestamp_do_not_correlate():
    assert sizes(run(raw("a", CREATED, 0, account=None), raw("b", SUDO, 60, account=None))) == [1, 1]
    assert sizes(run(raw("a", CREATED, 0, host=None), raw("b", SUDO, 60, host=None))) == [1, 1]
    assert sizes(run(raw("a", CREATED, None), raw("b", SUDO, 60))) == [1, 1]


def test_c1_and_c2_do_not_apply_generic_account_exclusion():
    c1 = run(raw("a", CREATED, 0, account="root"), raw("b", SUDO, 60, account="root"))
    c2 = run(raw("a", SSH, 0, account="root"), raw("b", CREATED, 60, account="root"))
    assert rule_ids(c1[0]) == ["C1"]
    assert rule_ids(c2[0]) == ["C2"]


# ---------------------------------------------------------------- C2
def test_c2_links_failed_ssh_to_later_account_creation_as_moderate():
    result = run(raw("a", SSH, 0, ip="10.1.1.1"), raw("b", CREATED, 3600))
    assert len(result) == 1
    (link,) = result[0].links
    assert link.rule_id == "C2"
    assert link.strength is Strength.MODERATE
    assert ("account", "ctl-corr-user") in link.shared_entities
    assert ("host", HOST) in link.shared_entities


def test_c2_makes_no_causal_or_access_claim():
    result = run(raw("a", SSH, 0, ip="10.1.1.1"), raw("b", CREATED, 3600))
    (link,) = result[0].links
    assert "does not show that the SSH source created the account" in link.limitations
    assert "does not establish causation" in link.limitations
    for word in FORBIDDEN_WORDS:
        assert word not in link.reason.lower()


def test_c2_reversed_equal_and_out_of_window_do_not_correlate():
    assert sizes(run(raw("a", CREATED, 0), raw("b", SSH, 60))) == [1, 1]
    assert sizes(run(raw("a", SSH, 0), raw("b", CREATED, 0))) == [1, 1]
    assert sizes(run(raw("a", SSH, 0), raw("b", CREATED, at=stamp(hours=24, milliseconds=1)))) == [1, 1]
    assert sizes(run(raw("a", SSH, 0), raw("b", CREATED, 24 * 3600))) == [2]


def test_c2_requires_same_account_and_host():
    assert sizes(run(raw("a", SSH, 0), raw("b", CREATED, 60, account="ctl-decoy-user"))) == [1, 1]
    assert sizes(run(raw("a", SSH, 0), raw("b", CREATED, 60, host="other"))) == [1, 1]


# ---------------------------------------------------------------- C3
def test_c3_recurrence_within_window_is_strong_and_boundary_inclusive():
    inside = run(raw("a", SSH, 0), raw("b", SSH, 3600))
    outside = run(raw("a", SSH, 0), raw("b", SSH, at=stamp(minutes=60, milliseconds=1)))
    assert rule_ids(inside[0]) == ["C3"]
    assert inside[0].links[0].strength is Strength.STRONG
    assert sizes(outside) == [1, 1]


def test_c3_equal_timestamps_still_link():
    assert sizes(run(raw("a", SSH, 0), raw("b", SSH, 0))) == [2]


def test_c3_requires_same_event_type_and_account():
    assert sizes(run(raw("a", SSH, 0), raw("b", SSH, 60, account="other"))) == [1, 1]
    assert sizes(run(raw("a", CREATED, 0), raw("b", SUDO, 0))) == [1, 1]  # equal ts: no C1


def test_c3_generic_account_is_not_a_sole_discriminating_identity():
    result = run(raw("a", SSH, 0, account="root"), raw("b", SSH, 60, account="root"))
    assert sizes(result) == [1, 1]
    # ...but the generic account is preserved as evidence and flagged.
    (ref,) = result[0].accounts
    assert ref.value == "root"
    assert ref.pivot_eligible is False
    assert ref.reason == "GENERIC_ACCOUNT"


# ---------------------------------------------------------------- C4
def test_c4_shared_ip_across_accounts_is_preserved_but_never_merges():
    result = run(
        raw("a-fail", SSH, 0, account="user-a", ip="203.0.113.7"),
        raw("b-fail", SSH, 60, account="user-b", ip="203.0.113.7"),
        raw("a-create", CREATED, 300, account="user-a"),
    )
    assert sizes(result) == [1, 2]
    by_ids = {inv.event_ids: inv for inv in result}
    a_inv = by_ids[("a-fail", "a-create")]
    b_inv = by_ids[("b-fail",)]

    assert rule_ids(a_inv) == ["C2"]  # C4 is not inside the account investigation
    assert b_inv.links == ()
    # The C4 relationship is preserved on BOTH sides as related context.
    (a_ctx,) = a_inv.related_context_links
    (b_ctx,) = b_inv.related_context_links
    assert a_ctx.link.rule_id == b_ctx.link.rule_id == "C4"
    assert a_ctx.other_investigation_id == b_inv.investigation_id
    assert b_ctx.other_investigation_id == a_inv.investigation_id
    assert a_ctx.this_event_id == "a-fail" and a_ctx.other_event_id == "b-fail"
    assert b_ctx.this_event_id == "b-fail" and b_ctx.other_event_id == "a-fail"
    assert a_ctx.link.merges_investigation is False


def test_c4_same_account_same_ip_yields_c3_and_c4_inside_one_investigation():
    result = run(raw("a", SSH, 0, ip="10.0.0.5"), raw("b", SSH, 30, ip="10.0.0.5"))
    assert rule_ids(result[0]) == ["C3", "C4"]
    assert result[0].related_context_links == ()


def test_c4_does_not_require_same_host():
    result = run(
        raw("a", SSH, 0, account="x", host="host-1", ip="10.0.0.5"),
        raw("b", SSH, 30, account="y", host="host-2", ip="10.0.0.5"),
    )
    assert sizes(result) == [1, 1]
    assert result[0].related_context_links[0].link.rule_id == "C4"


def test_c4_missing_invalid_unusable_or_out_of_window_ip_creates_no_link():
    def c4_links(first_ip, second_ip, gap=30):
        result = run(raw("a", SSH, 0, account="x", ip=first_ip),
                     raw("b", SSH, gap, account="y", ip=second_ip))
        return sorted({c.link.link_id for inv in result for c in inv.related_context_links})

    assert c4_links(None, None) == []
    assert c4_links("not-an-ip", "not-an-ip") == []
    assert c4_links("127.0.0.1", "127.0.0.1") == []
    assert c4_links("0.0.0.0", "0.0.0.0") == []
    assert c4_links("224.0.0.1", "224.0.0.1") == []
    assert c4_links("10.0.0.5", "10.0.0.5", gap=3601) == []
    assert len(c4_links("10.0.0.5", "10.0.0.5", gap=3600)) == 1


def test_invalid_ip_becomes_none_with_evidence_gap():
    event = normalize_event(raw("a", SSH, 0, ip="999.1.1.1"))
    assert event.source_ip is None
    assert any(g.field_name == "source_ip" and g.reason is GapReason.UNPARSEABLE_VALUE
               for g in event.evidence_gaps)


def test_default_infrastructure_list_is_empty_and_lab_ip_is_usable():
    assert CorrelationConfig().infrastructure_ips == frozenset()
    result = run(raw("a", SSH, 0, ip="192.168.145.1"))
    (ref,) = result[0].source_ips
    assert ref.pivot_eligible is True and ref.reason is None


def test_configured_infrastructure_ip_is_preserved_but_not_a_pivot():
    config = CorrelationConfig(infrastructure_ips=frozenset({"192.168.145.1"}))
    result = run(
        raw("a", SSH, 0, account="x", ip="192.168.145.1"),
        raw("b", SSH, 30, account="y", ip="192.168.145.1"),
        config=config,
    )
    assert sizes(result) == [1, 1]
    assert all(not inv.related_context_links for inv in result)  # no C4 link
    for inv in result:
        (ref,) = inv.source_ips
        assert ref.value == "192.168.145.1"
        assert ref.pivot_eligible is False
        assert ref.reason == "INFRASTRUCTURE_IP_CONFIGURED"


# ------------------------------------------------- host / time / None safeguards
def test_same_host_alone_does_not_correlate_unrelated_identities():
    result = run(
        raw("a", CREATED, 0, account="alice"),
        raw("b", SUDO, 60, account="bob"),
        raw("c", SSH, 120, account="carol"),
    )
    assert sizes(result) == [1, 1, 1]


def test_time_proximity_alone_does_not_correlate_unrelated_identities():
    result = run(
        raw("a", CREATED, 0, account="alice", host="host-1"),
        raw("b", SUDO, 0, account="bob", host="host-2"),
        raw("c", SSH, 0, account="carol", host="host-3"),
    )
    assert sizes(result) == [1, 1, 1]


def test_none_never_matches_none():
    # Same host/type/time, both accounts unknown.
    assert sizes(run(raw("a", SSH, 0, account=None), raw("b", SSH, 1, account=None))) == [1, 1]
    # Same account/type/time, both hosts unknown.
    assert sizes(run(raw("a", SSH, 0, host=None), raw("b", SSH, 1, host=None))) == [1, 1]
    # Both source IPs unknown.
    result = run(raw("a", SSH, 0, account="x"), raw("b", SSH, 1, account="y"))
    assert all(not inv.related_context_links for inv in result)


def test_events_without_timestamps_never_correlate_by_time_rules():
    result = run(raw("a", CREATED, None), raw("b", SUDO, None), raw("c", SSH, None))
    assert sizes(result) == [1, 1, 1]


# ---------------------------------------------------------------- caps
def test_size_cap_is_enforced_with_warnings():
    events = [raw(f"e{i:02d}", SSH, i) for i in range(21)]
    result = run(*events)
    assert max(len(i.event_ids) for i in result) <= 20
    assert sizes(result) == [1, 20]
    assert all(inv.warnings for inv in result)
    assert {w.code for inv in result for w in inv.warnings} == {"SIZE_CAP"}


def test_span_cap_is_enforced_with_warnings():
    config = CorrelationConfig(max_investigation_span=timedelta(minutes=30))
    result = run(
        raw("a", SSH, 0), raw("b", SSH, 20 * 60), raw("c", SSH, 40 * 60),
        config=config,
    )
    assert sizes(result) == [1, 2]
    assert {w.code for inv in result for w in inv.warnings} == {"SPAN_CAP"}


def test_default_config_values_are_the_documented_lab_defaults():
    config = CorrelationConfig()
    assert config.c1_window == timedelta(hours=24)
    assert config.c2_window == timedelta(hours=24)
    assert config.c3_window == timedelta(minutes=60)
    assert config.c4_window == timedelta(minutes=60)
    assert config.max_investigation_span == timedelta(hours=24)
    assert config.max_investigation_events == 20


# ---------------------------------------------------------------- IDs
def test_investigation_id_depends_only_on_sorted_membership():
    forward = run(raw("a", CREATED, 0), raw("b", SUDO, 60))
    backward = run(raw("b", SUDO, 60), raw("a", CREATED, 0))
    assert forward[0].investigation_id == backward[0].investigation_id

    changed = run(raw("a", CREATED, 0), raw("b", SUDO, 60), raw("c", SUDO, 120))
    assert changed[0].investigation_id != forward[0].investigation_id


def test_investigation_id_format_and_independent_recomputation():
    result = run(raw("evt-2", CREATED, 0), raw("evt-1", SUDO, 60))
    inv_id = result[0].investigation_id
    expected = "INV-" + hashlib.sha256(
        json.dumps(["evt-1", "evt-2"], separators=(",", ":")).encode()
    ).hexdigest()[:12].upper()
    assert inv_id == expected
    assert compute_investigation_id(["evt-2", "evt-1"]) == expected
    assert inv_id.startswith("INV-") and len(inv_id) == 16


# ---------------------------------------------------------------- normalization
@pytest.mark.parametrize(
    "text, expected",
    [
        ("2026-10-06T00:08:39Z", datetime(2026, 10, 6, 0, 8, 39, tzinfo=timezone.utc)),
        ("2026-10-06T00:08:39z", datetime(2026, 10, 6, 0, 8, 39, tzinfo=timezone.utc)),
        ("2026-10-06T00:08:39.1Z", datetime(2026, 10, 6, 0, 8, 39, 100000, tzinfo=timezone.utc)),
        ("2026-10-06T00:08:39.271Z", datetime(2026, 10, 6, 0, 8, 39, 271000, tzinfo=timezone.utc)),
        ("2026-10-06T00:08:39.123456Z", datetime(2026, 10, 6, 0, 8, 39, 123456, tzinfo=timezone.utc)),
        ("2026-10-06T00:08:39.1234567Z", datetime(2026, 10, 6, 0, 8, 39, 123456, tzinfo=timezone.utc)),
        ("2026-10-06T00:08:39+00:00", datetime(2026, 10, 6, 0, 8, 39, tzinfo=timezone.utc)),
        ("2026-10-06T05:30:00+05:30", datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)),
        ("2026-10-05T19:00:00-05:00", datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)),
    ],
)
def test_valid_timezone_aware_timestamps_normalise_to_utc(text, expected):
    event = normalize_event(raw("a", CREATED, text))
    assert event.timestamp == expected
    assert event.timestamp.utcoffset() == timedelta(0)
    assert event.evidence_gaps == ()


@pytest.mark.parametrize(
    "value, reason",
    [
        ("2026-10-06T00:08:39", GapReason.TIMEZONE_MISSING),  # naive: never assume a zone
        ("2026-10-06", GapReason.TIMEZONE_MISSING),
        ("not-a-timestamp", GapReason.UNPARSEABLE_VALUE),
        (1759708800, GapReason.UNPARSEABLE_VALUE),
    ],
)
def test_naive_or_invalid_timestamps_fail_closed_with_gap(value, reason):
    event = normalize_event(
        {"event_id": "a", "event_type": CREATED, "timestamp": value,
         "host": HOST, "target_account": "ctl-corr-user"}
    )
    assert event.timestamp is None
    assert any(g.field_name == "timestamp" and g.reason is reason
               for g in event.evidence_gaps)


def test_blank_values_become_none_and_gaps_are_recorded():
    event = normalize_event(raw("a", SSH, 0, account="   ", host=""))
    assert event.target_account is None and event.host is None
    gap_fields = {g.field_name for g in event.evidence_gaps}
    assert {"host", "target_account", "source_ip"} <= gap_fields


def test_unknown_event_type_is_ingested_as_unknown_singleton():
    result = run(raw("a", "something_new", 0))
    assert sizes(result) == [1]
    event = normalize_event(raw("a", "something_new", 0))
    assert event.event_type is EventType.UNKNOWN
    assert any(g.reason is GapReason.UNRECOGNIZED_VALUE for g in event.evidence_gaps)


def test_missing_or_blank_event_id_is_rejected_and_duplicates_raise():
    with pytest.raises(NormalizationError):
        normalize_event({"event_type": SSH})
    with pytest.raises(NormalizationError):
        normalize_event({"event_id": "  ", "event_type": SSH})
    with pytest.raises(ValueError):
        run(raw("dup", SSH, 0), raw("dup", SSH, 5))


def test_scenario_level_values_are_never_used_as_evidence():
    scenario = {
        "host": HOST,
        "primary_account": "ctl-corr-user",
        "decoy_account": "ctl-decoy-user",
        "events": [{"event_id": "a", "event_type": CREATED, "timestamp": stamp(0)}],
    }
    (event,) = load_events_from_scenario(scenario)
    assert event.host is None and event.target_account is None
    with pytest.raises(NormalizationError):
        load_events_from_scenario({"host": HOST})


def test_mitre_is_preserved_only_when_supplied_and_never_inferred():
    plain = run(raw("a", CREATED, 0), raw("b", SUDO, 60))
    assert plain[0].mitre_techniques == ()

    supplied = run(raw("a", CREATED, 0, mitre_technique="T1136.001"), raw("b", SUDO, 60))
    assert supplied[0].mitre_techniques == (("T1136.001", ("a",)),)


def test_no_actor_or_authentication_success_is_ever_inferred():
    result = run(raw("a", SSH, 0, ip="10.0.0.5"), raw("b", CREATED, 60))
    inv = result[0]
    assert "actor_user" in inv.unavailable_telemetry
    assert "session_id" in inv.unavailable_telemetry
    event = normalize_event(raw("a", CREATED, 0))
    assert not hasattr(event, "actor_user")
    assert not hasattr(event, "successful_authentication")


# ---------------------------------------------------------------- invariants
def test_timeline_is_chronological_for_shuffled_input():
    events = [
        raw("late", SUDO, 900),
        raw("early", SSH, 0, ip="10.0.0.5"),
        raw("middle", CREATED, 300),
    ]
    result = run(*events)
    assert len(result) == 1
    stamps = [t.timestamp for t in result[0].timeline]
    assert stamps == sorted(stamps)
    assert [t.event_id for t in result[0].timeline] == ["early", "middle", "late"]
    assert result[0].event_ids == ("early", "middle", "late")


def test_results_are_deterministic_across_input_orders_and_repeated_runs():
    events = [
        raw("a", SSH, 0, ip="10.0.0.5"),
        raw("b", SSH, 10, ip="10.0.0.5"),
        raw("c", CREATED, 600),
        raw("d", SUDO, 900),
        raw("e", CREATED, 1000, account="decoy"),
    ]
    normalized = [normalize_event(e) for e in events]
    baseline = correlate(normalized)
    orders = [
        list(reversed(normalized)),
        [normalized[i] for i in (3, 0, 4, 1, 2)],
        [normalized[i] for i in (2, 4, 1, 3, 0)],
        [normalized[i] for i in (4, 3, 2, 1, 0)],
    ]
    for order in orders:
        assert correlate(order) == baseline
    for _ in range(3):
        assert correlate(normalized) == baseline


def test_analyst_review_is_always_required_and_cannot_be_disabled():
    result = run(raw("a", CREATED, 0), raw("b", SUDO, 60), raw("x", SSH, 0, account="z"))
    assert result and all(inv.analyst_review_required is True for inv in result)
    with pytest.raises(AttributeError):
        result[0].analyst_review_required = False


def test_every_link_carries_reason_and_limitations_without_interpretive_claims():
    result = run(
        raw("a", SSH, 0, ip="10.0.0.5"), raw("b", SSH, 5, ip="10.0.0.5"),
        raw("c", CREATED, 100), raw("d", SUDO, 200),
    )
    links = [l for inv in result for l in inv.links]
    assert {l.rule_id for l in links} == {"C1", "C2", "C3", "C4"}
    for link in links:
        assert "does not establish causation" in link.limitations
        assert link.reason
        for word in FORBIDDEN_WORDS:
            assert word not in link.reason.lower()
    for entry in (t for inv in result for t in inv.timeline):
        for word in FORBIDDEN_WORDS:
            assert word not in entry.summary.lower()


def test_correlation_engine_does_not_import_the_ai_layer():
    import backend.app.correlation.engine as engine
    import backend.app.correlation.normalization as normalization

    for module in (engine, normalization):
        names = " ".join(vars(module))
        assert "ollama" not in names.lower()
        assert "generate_ai_summary" not in names


def test_invalid_config_is_rejected():
    with pytest.raises(ValueError):
        CorrelationConfig(max_investigation_events=0)
    with pytest.raises(ValueError):
        CorrelationConfig(c3_window=timedelta(seconds=-1))
    with pytest.raises(ValueError):
        CorrelationConfig(infrastructure_ips=frozenset({"not-an-ip"}))
