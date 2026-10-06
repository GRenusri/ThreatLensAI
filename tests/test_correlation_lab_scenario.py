"""Tests against the real controlled lab evidence
(backend/data/correlation_lab_scenario.json)."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from backend.app.correlation import (
    correlate,
    load_events_from_scenario,
)
from backend.app.correlation.models import Strength

SCENARIO_PATH = (
    Path(__file__).resolve().parents[1] / "backend" / "data" / "correlation_lab_scenario.json"
)

PRIMARY = (
    "corr-ssh-001", "corr-ssh-002", "corr-ssh-003", "corr-account-001", "corr-sudo-001",
)
DECOY = ("corr-decoy-001",)
FORBIDDEN_WORDS = ("attack", "compromise", "malicious", "caused", "breach")


def load_raw():
    return json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))


def lab_investigations(data=None):
    return correlate(load_events_from_scenario(data or load_raw()))


def split(investigations):
    by_ids = {inv.event_ids: inv for inv in investigations}
    return by_ids[PRIMARY], by_ids[DECOY]


def test_lab_evidence_loads_six_events_with_expected_ids():
    events = load_events_from_scenario(load_raw())
    assert [e.event_id for e in events] == list(PRIMARY) + list(DECOY)
    assert all(e.timestamp is not None and e.host == "soc-linux-01" for e in events)
    assert all(e.evidence_gaps == () for e in events)


def test_lab_scenario_produces_primary_investigation_and_separate_decoy():
    investigations = lab_investigations()
    assert len(investigations) == 2
    assert {inv.event_ids for inv in investigations} == {PRIMARY, DECOY}


def test_c2_links_each_failed_ssh_event_to_account_creation_as_moderate():
    primary, _ = split(lab_investigations())
    c2 = {l.earlier_event_id: l for l in primary.links if l.rule_id == "C2"}
    assert set(c2) == {"corr-ssh-001", "corr-ssh-002", "corr-ssh-003"}
    expected = {
        "corr-ssh-001": timedelta(minutes=24, seconds=18, milliseconds=166),
        "corr-ssh-002": timedelta(minutes=24, seconds=1, milliseconds=360),
        "corr-ssh-003": timedelta(minutes=23, seconds=57, milliseconds=207),
    }
    for event_id, link in c2.items():
        assert link.later_event_id == "corr-account-001"
        assert link.strength is Strength.MODERATE
        assert link.time_difference == expected[event_id]
        assert ("account", "ctl-corr-user") in link.shared_entities
        assert ("host", "soc-linux-01") in link.shared_entities


def test_c1_links_account_creation_to_sudo_addition_as_strong():
    primary, _ = split(lab_investigations())
    (c1,) = [l for l in primary.links if l.rule_id == "C1"]
    assert (c1.earlier_event_id, c1.later_event_id) == ("corr-account-001", "corr-sudo-001")
    assert c1.strength is Strength.STRONG
    assert c1.time_difference == timedelta(minutes=8, seconds=34, milliseconds=971)
    assert ("account", "ctl-corr-user") in c1.shared_entities


def test_c3_and_c4_link_the_three_failed_ssh_events_inside_the_investigation():
    primary, _ = split(lab_investigations())
    pairs = {("corr-ssh-001", "corr-ssh-002"), ("corr-ssh-001", "corr-ssh-003"),
             ("corr-ssh-002", "corr-ssh-003")}
    for rule, strength in (("C3", Strength.STRONG), ("C4", Strength.MODERATE)):
        links = [l for l in primary.links if l.rule_id == rule]
        assert {(l.earlier_event_id, l.later_event_id) for l in links} == pairs
        assert all(l.strength is strength for l in links)
    c4 = [l for l in primary.links if l.rule_id == "C4"]
    assert all(("source_ip", "192.168.145.1") in l.shared_entities for l in c4)
    assert all(not l.merges_investigation for l in c4)
    assert len(primary.links) == 10  # C1 x1, C2 x3, C3 x3, C4 x3
    assert primary.related_context_links == ()


def test_decoy_account_is_separate_and_has_no_links():
    investigations = lab_investigations()
    primary, decoy = split(investigations)
    assert decoy.links == () and decoy.related_context_links == ()
    assert "corr-decoy-001" not in primary.event_ids
    assert [a.value for a in decoy.accounts] == ["ctl-decoy-user"]


def test_decoy_creation_after_sudo_never_links_to_the_sudo_event():
    investigations = lab_investigations()
    all_links = [l for inv in investigations for l in inv.links]
    assert not any("corr-decoy-001" in (l.earlier_event_id, l.later_event_id)
                   for l in all_links)


def test_lab_timeline_is_ordered_and_chronological():
    primary, decoy = split(lab_investigations())
    assert [t.event_id for t in primary.timeline] == list(PRIMARY)
    stamps = [t.timestamp for t in primary.timeline]
    assert stamps == sorted(stamps)
    assert primary.timeline[0].timestamp == datetime(
        2026, 10, 5, 23, 44, 21, 105000, tzinfo=timezone.utc
    )


def test_lab_entities_are_preserved_with_pivot_flags():
    primary, _ = split(lab_investigations())
    assert [a.value for a in primary.accounts] == ["ctl-corr-user"]
    assert primary.accounts[0].pivot_eligible is True
    assert [h.value for h in primary.hosts] == ["soc-linux-01"]
    (ip,) = primary.source_ips
    assert ip.value == "192.168.145.1"
    assert ip.pivot_eligible is True and ip.reason is None


def test_lab_makes_no_unsupported_inference():
    investigations = lab_investigations()
    for inv in investigations:
        assert inv.mitre_techniques == ()
        assert inv.evidence_gaps == ()
        assert inv.warnings == ()
        assert inv.analyst_review_required is True
        assert "actor_user" in inv.unavailable_telemetry
        for entry in inv.timeline:
            for word in FORBIDDEN_WORDS:
                assert word not in entry.summary.lower()
        for link in inv.links:
            for word in FORBIDDEN_WORDS:
                assert word not in link.reason.lower()


def test_useradd_source_is_kept_as_origin_not_as_an_ip():
    events = {e.event_id: e for e in load_events_from_scenario(load_raw())}
    created = events["corr-account-001"]
    assert created.origin == "/dev/pts/1"
    assert created.source_ip is None
    assert (created.uid, created.gid) == (1001, 1001)


def test_scenario_level_labels_do_not_influence_the_result():
    baseline = lab_investigations()
    data = load_raw()
    data["primary_account"] = "ctl-decoy-user"
    data["decoy_account"] = "ctl-corr-user"
    data["host"] = "some-other-host"
    data["authorized_test"] = False
    assert lab_investigations(data) == baseline


def test_lab_result_is_input_order_independent_and_repeatable():
    events = load_events_from_scenario(load_raw())
    baseline = correlate(events)
    orders = [
        list(reversed(events)),
        [events[i] for i in (3, 0, 5, 1, 4, 2)],
        [events[i] for i in (5, 3, 1, 4, 0, 2)],
        [events[i] for i in (2, 4, 0, 5, 1, 3)],
    ]
    for order in orders:
        assert correlate(order) == baseline
    for _ in range(3):
        assert correlate(events) == baseline
