"""API tests for the Phase 2 investigation endpoints.

FastAPI's ``TestClient`` needs an extra HTTP-client package that is not part of
the project's dependencies, so these tests call the real ASGI application
through a tiny standard-library harness instead.  No network access is used.
"""

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.app import investigations_api
from backend.app.main import app

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_SCENARIO = REPO_ROOT / "backend" / "data" / "correlation_lab_scenario.json"

PRIMARY = [
    "corr-ssh-001",
    "corr-ssh-002",
    "corr-ssh-003",
    "corr-account-001",
    "corr-sudo-001",
]
DECOY = ["corr-decoy-001"]

TIMESTAMP_FORMAT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
FORBIDDEN_WORDS = ("attack", "compromise", "malicious", "caused", "breach")
FORBIDDEN_KEYS = {
    "actor_user",
    "session_id",
    "successful_authentication",
    "authentication_success",
    "risk_score",
    "risk",
    "severity",
    "attribution",
    "attributed_to",
    "verdict",
    "confidence",
}


# ------------------------------------------------------------------ harness
async def _call(method, path):
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await asyncio.sleep(3600)

    result = {"status": None, "body": b""}

    async def send(message):
        if message["type"] == "http.response.start":
            result["status"] = message["status"]
        elif message["type"] == "http.response.body":
            result["body"] += message.get("body", b"")

    await app(scope, receive, send)
    return result["status"], result["body"]


def get(path):
    status, body = asyncio.run(_call("GET", path))
    return status, json.loads(body)


def get_raw(path):
    return asyncio.run(_call("GET", path))


def walk(value):
    """Yield every dict key and every string value in a parsed JSON document."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield ("key", key)
            yield from walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk(item)
    elif isinstance(value, str):
        yield ("str", value)


def detail_for(event_ids):
    status, listing = get("/investigations")
    assert status == 200
    match = [i for i in listing["investigations"] if i["event_ids"] == event_ids]
    assert len(match) == 1, f"expected exactly one investigation with {event_ids}"
    status, detail = get(f"/investigations/{match[0]['investigation_id']}")
    assert status == 200
    return detail


def write_scenario(tmp_path, monkeypatch, content):
    path = tmp_path / "scenario.json"
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content if isinstance(content, str) else json.dumps(content))
    monkeypatch.setattr(investigations_api, "SCENARIO_PATH", path)
    return path


def ssh_event(event_id, offset_seconds, account="ctl-corr-user", ip="192.168.145.1"):
    base = datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)
    stamp = (base + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z")
    return {
        "event_id": event_id,
        "event_type": "failed_ssh_authentication",
        "timestamp": stamp,
        "host": "soc-linux-01",
        "target_account": account,
        "source_ip": ip,
    }


def created_event(event_id, offset_seconds, account):
    event = ssh_event(event_id, offset_seconds, account)
    event["event_type"] = "local_account_created"
    del event["source_ip"]
    return event


# ------------------------------------------------- 1-3 investigation grouping
def test_list_returns_exactly_the_two_controlled_investigations():
    status, body = get("/investigations")
    assert status == 200
    assert body["count"] == 2
    assert len(body["investigations"]) == 2
    assert [i["event_ids"] for i in body["investigations"]] == [PRIMARY, DECOY]


def test_primary_investigation_contains_exactly_the_correlated_sequence():
    _, body = get("/investigations")
    primary = body["investigations"][0]
    assert primary["event_ids"] == PRIMARY
    assert primary["event_count"] == 5
    assert primary["accounts"] == ["ctl-corr-user"]
    assert primary["hosts"] == ["soc-linux-01"]
    assert primary["source_ips"] == ["192.168.145.1"]
    assert primary["rule_ids"] == ["C1", "C2", "C3", "C4"]
    assert primary["first_event_timestamp"] == "2026-10-05T23:44:21.105000Z"
    assert primary["last_event_timestamp"] == "2026-10-06T00:17:14.242000Z"
    assert primary["warning_count"] == 0
    assert primary["evidence_gap_count"] == 0
    assert primary["related_context_link_count"] == 0


def test_decoy_account_remains_isolated():
    _, body = get("/investigations")
    decoy = body["investigations"][1]
    assert decoy["event_ids"] == DECOY
    assert decoy["accounts"] == ["ctl-decoy-user"]
    assert decoy["rule_ids"] == []
    assert decoy["related_context_link_count"] == 0
    assert "corr-decoy-001" not in body["investigations"][0]["event_ids"]

    detail = detail_for(DECOY)
    assert detail["links"] == [] and detail["related_context_links"] == []


def test_list_summaries_do_not_contain_full_investigation_graphs():
    _, body = get("/investigations")
    for summary in body["investigations"]:
        assert "timeline" not in summary
        assert "links" not in summary
        assert "related_context_links" not in summary


# ----------------------------------------------------------- 4 timeline order
def test_timeline_ordering_survives_serialization():
    detail = detail_for(PRIMARY)
    assert [t["event_id"] for t in detail["timeline"]] == PRIMARY
    assert detail["event_ids"] == PRIMARY
    stamps = [t["timestamp"] for t in detail["timeline"]]
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == len(stamps)


# ------------------------------------------------ 5-6 rules, strengths, C4
def test_c1_c2_c3_c4_and_strengths_survive_serialization():
    detail = detail_for(PRIMARY)
    expected_strength = {"C1": "STRONG", "C2": "MODERATE", "C3": "STRONG", "C4": "MODERATE"}
    by_rule = {}
    for link in detail["links"]:
        by_rule.setdefault(link["rule_id"], []).append(link)

    assert {rule: len(links) for rule, links in by_rule.items()} == {
        "C1": 1, "C2": 3, "C3": 3, "C4": 3,
    }
    for rule, links in by_rule.items():
        assert all(l["strength"] == expected_strength[rule] for l in links)

    (c1,) = by_rule["C1"]
    assert (c1["earlier_event_id"], c1["later_event_id"]) == ("corr-account-001", "corr-sudo-001")
    assert {"kind": "account", "value": "ctl-corr-user"} in c1["shared_entities"]
    assert {"kind": "host", "value": "soc-linux-01"} in c1["shared_entities"]
    assert {l["earlier_event_id"] for l in by_rule["C2"]} == {
        "corr-ssh-001", "corr-ssh-002", "corr-ssh-003",
    }
    assert all(l["later_event_id"] == "corr-account-001" for l in by_rule["C2"])
    assert all(
        {"kind": "source_ip", "value": "192.168.145.1"} in l["shared_entities"]
        for l in by_rule["C4"]
    )
    for link in detail["links"]:
        assert link["reason"] and link["limitations"]


def test_c4_remains_non_merging():
    detail = detail_for(PRIMARY)
    c4_links = [l for l in detail["links"] if l["rule_id"] == "C4"]
    assert c4_links and all(l["merges_investigation"] is False for l in c4_links)
    for link in detail["links"]:
        if link["rule_id"] in ("C1", "C2", "C3"):
            assert link["merges_investigation"] is True


def test_engine_text_is_passed_through_unchanged():
    from backend.app.correlation import correlate, load_events_from_scenario

    engine = correlate(load_events_from_scenario(json.loads(REAL_SCENARIO.read_text())))[0]
    detail = detail_for(PRIMARY)
    assert [l["reason"] for l in detail["links"]] == [l.reason for l in engine.links]
    assert [l["limitations"] for l in detail["links"]] == [l.limitations for l in engine.links]
    assert [t["summary"] for t in detail["timeline"]] == [t.summary for t in engine.timeline]


# ------------------------------------------ 7-8 review flag, no conclusions
def test_analyst_review_required_is_explicitly_true_everywhere():
    _, listing = get("/investigations")
    for summary in listing["investigations"]:
        assert summary["analyst_review_required"] is True
        _, detail = get(f"/investigations/{summary['investigation_id']}")
        assert detail["analyst_review_required"] is True


def test_no_unsupported_conclusions_or_inferred_fields_appear():
    _, listing = get("/investigations")
    documents = [listing]
    for summary in listing["investigations"]:
        documents.append(get(f"/investigations/{summary['investigation_id']}")[1])

    for document in documents:
        keys = {value for kind, value in walk(document) if kind == "key"}
        assert not (keys & FORBIDDEN_KEYS), keys & FORBIDDEN_KEYS

    for document in documents[1:]:
        # actor_user / session_id appear only as unavailable telemetry.
        assert document["unavailable_telemetry"] == ["actor_user", "session_id"]
        assert document["mitre_techniques"] == []
        for entry in document["timeline"]:
            for word in FORBIDDEN_WORDS:
                assert word not in entry["summary"].lower()
        for link in document["links"]:
            for word in FORBIDDEN_WORDS:
                assert word not in link["reason"].lower()


def test_c2_stays_correlation_not_causation():
    detail = detail_for(PRIMARY)
    for link in (l for l in detail["links"] if l["rule_id"] == "C2"):
        assert "does not establish causation" in link["limitations"]
        assert "does not show that the SSH source created the account" in link["limitations"]
        assert "created by" not in link["reason"].lower()


def test_scenario_level_labels_are_not_exposed_as_evidence():
    _, listing = get("/investigations")
    text = json.dumps(listing)
    for label in ("primary_account", "decoy_account", "authorized_test"):
        assert label not in text
    assert listing["evidence_source"] == {
        "type": "controlled_lab_scenario",
        "scenario_file": "correlation_lab_scenario.json",
        "live_sentinel_ingestion": False,
    }


# --------------------------------------------------------- 9-10 lookup / 404
def test_valid_investigation_lookup_returns_the_correct_investigation():
    _, listing = get("/investigations")
    for summary in listing["investigations"]:
        status, detail = get(f"/investigations/{summary['investigation_id']}")
        assert status == 200
        assert detail["investigation_id"] == summary["investigation_id"]
        assert detail["event_ids"] == summary["event_ids"]
        assert detail["event_count"] == summary["event_count"]


def test_unknown_investigation_id_returns_404_not_a_200_error_body():
    for bad_id in ("INV-DOESNOTEXIST", "nope", "inv-f0e9505189fe"):
        status, body = get(f"/investigations/{bad_id}")
        assert status == 404
        assert body["detail"]["code"] == "INVESTIGATION_NOT_FOUND"
        assert bad_id not in json.dumps(body)  # input is not reflected


def test_lookup_is_case_sensitive():
    _, listing = get("/investigations")
    valid = listing["investigations"][0]["investigation_id"]
    status, _ = get(f"/investigations/{valid.lower()}")
    assert status == 404


# ---------------------------------------------- 11-13 stable serialization
def test_datetimes_use_one_explicit_utc_format():
    detail = detail_for(PRIMARY)
    stamps = [t["timestamp"] for t in detail["timeline"]]
    for link in detail["links"]:
        stamps += [link["earlier_timestamp"], link["later_timestamp"]]
    assert all(TIMESTAMP_FORMAT.match(s) for s in stamps)
    assert detail["timeline"][0]["timestamp"] == "2026-10-05T23:44:21.105000Z"
    assert detail["timeline"][3]["timestamp"] == "2026-10-06T00:08:39.271000Z"


def test_whole_second_timestamp_keeps_the_same_format():
    assert investigations_api.to_utc_iso(
        datetime(2026, 10, 6, 0, 0, 0, tzinfo=timezone.utc)
    ) == "2026-10-06T00:00:00.000000Z"
    offset = datetime(2026, 10, 6, 5, 30, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert investigations_api.to_utc_iso(offset) == "2026-10-06T00:00:00.000000Z"
    assert investigations_api.to_utc_iso(None) is None
    with pytest.raises(ValueError):
        investigations_api.to_utc_iso(datetime(2026, 10, 6))


def test_timedeltas_are_integer_milliseconds():
    detail = detail_for(PRIMARY)
    by_id = {l["link_id"]: l for l in detail["links"]}
    assert by_id["C1:corr-account-001->corr-sudo-001"]["time_difference_ms"] == 514971
    assert by_id["C2:corr-ssh-001->corr-account-001"]["time_difference_ms"] == 1458166
    assert by_id["C2:corr-ssh-002->corr-account-001"]["time_difference_ms"] == 1441360
    assert by_id["C2:corr-ssh-003->corr-account-001"]["time_difference_ms"] == 1437207
    assert by_id["C3:corr-ssh-002->corr-ssh-003"]["time_difference_ms"] == 4153
    for link in detail["links"]:
        assert type(link["time_difference_ms"]) is int
        assert "time_difference" not in link


def test_millisecond_conversion_truncates_and_is_never_negative():
    assert investigations_api.to_millis(timedelta(microseconds=1999)) == 1
    assert investigations_api.to_millis(timedelta(0)) == 0
    assert investigations_api.to_millis(timedelta(hours=24)) == 86_400_000


def test_strength_is_textual_not_numeric():
    detail = detail_for(PRIMARY)
    assert {l["strength"] for l in detail["links"]} == {"STRONG", "MODERATE"}
    assert all(isinstance(l["strength"], str) for l in detail["links"])


# ---------------------------------------- 14 evidence failures fail closed
def _assert_fails_closed(expected_code):
    for path in ("/investigations", "/investigations/INV-F0E9505189FE"):
        status, body = get(path)
        assert status == 503, f"{path} returned {status}"
        assert body["detail"]["code"] == expected_code
        assert set(body) == {"detail"}  # never a successful-looking body
        assert "investigations" not in body and "count" not in body


@pytest.mark.parametrize(
    "content, code",
    [
        ("{ this is not json", "EVIDENCE_MALFORMED"),
        ("", "EVIDENCE_MALFORMED"),
        (b"\xff\xfe\x00 not utf-8", "EVIDENCE_MALFORMED"),
        ([{"event_id": "a"}], "EVIDENCE_INVALID"),  # top level is a list
        ({"scenario_id": "x"}, "EVIDENCE_INVALID"),  # events missing
        ({"events": "not-a-list"}, "EVIDENCE_INVALID"),
        ({"events": [42]}, "EVIDENCE_INVALID"),  # event is not an object
        ({"events": [{"event_type": "failed_ssh_authentication"}]}, "EVIDENCE_INVALID"),
        ({"events": [{"event_id": "   ", "event_type": "x"}]}, "EVIDENCE_INVALID"),
        ({"events": []}, "EVIDENCE_EMPTY"),
        (
            {"events": [ssh_event("dup", 0), ssh_event("dup", 5)]},
            "EVIDENCE_DUPLICATE_EVENT_ID",
        ),
    ],
)
def test_bad_evidence_fails_closed_with_503(tmp_path, monkeypatch, content, code):
    write_scenario(tmp_path, monkeypatch, content)
    _assert_fails_closed(code)


def test_missing_scenario_file_fails_closed_with_503(tmp_path, monkeypatch):
    monkeypatch.setattr(investigations_api, "SCENARIO_PATH", tmp_path / "absent.json")
    _assert_fails_closed("EVIDENCE_UNAVAILABLE")


def test_unreadable_scenario_path_fails_closed_with_503(tmp_path, monkeypatch):
    monkeypatch.setattr(investigations_api, "SCENARIO_PATH", tmp_path)  # a directory
    _assert_fails_closed("EVIDENCE_UNAVAILABLE")


def test_evidence_errors_do_not_leak_paths_or_raw_evidence(tmp_path, monkeypatch):
    secret = "SECRET-MARKER-12345"
    path = write_scenario(tmp_path, monkeypatch, '{"events": [{"event_id": "' + secret)
    status, raw = get_raw("/investigations")
    text = raw.decode()
    assert status == 503
    assert secret not in text
    assert str(tmp_path) not in text and path.name not in text
    assert "Traceback" not in text


def test_nonfatal_evidence_quality_problems_stay_visible_as_gaps(tmp_path, monkeypatch):
    bad_time = created_event("e1", 0, "ctl-corr-user")
    bad_time["timestamp"] = "not-a-timestamp"
    write_scenario(tmp_path, monkeypatch, {"events": [bad_time]})

    status, listing = get("/investigations")
    assert status == 200 and listing["count"] == 1
    summary = listing["investigations"][0]
    assert summary["evidence_gap_count"] == 1
    assert summary["first_event_timestamp"] is None
    assert summary["last_event_timestamp"] is None

    _, detail = get(f"/investigations/{summary['investigation_id']}")
    assert detail["timeline"][0]["timestamp"] is None  # explicit null, not invented
    assert detail["evidence_gaps"] == [
        {"event_id": "e1", "field_name": "timestamp", "reason": "unparseable_value"}
    ]


def test_unexpected_internal_failure_returns_generic_500(monkeypatch):
    def explode(events):
        raise RuntimeError("boom /secret/path/for/debugging")

    monkeypatch.setattr(investigations_api, "correlate", explode)
    status, raw = get_raw("/investigations")
    text = raw.decode()
    assert status == 500
    assert json.loads(text)["detail"]["code"] == "INTERNAL_ERROR"
    assert "boom" not in text and "/secret/path" not in text and "Traceback" not in text


# ------------------------------------------- 15 working-directory independence
def test_scenario_path_is_absolute_and_derived_from_the_module_location():
    assert investigations_api.SCENARIO_PATH.is_absolute()
    assert investigations_api.SCENARIO_PATH == REAL_SCENARIO


def test_endpoints_work_from_another_working_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert not Path("backend/data/correlation_lab_scenario.json").exists()
    status, body = get("/investigations")
    assert status == 200 and body["count"] == 2
    valid = body["investigations"][0]["investigation_id"]
    assert get(f"/investigations/{valid}")[0] == 200


# ---------------------------------------------------------- 16 determinism
def test_repeated_requests_produce_equivalent_json():
    first = get_raw("/investigations")
    ids = [i["investigation_id"] for i in json.loads(first[1])["investigations"]]
    details = [get_raw(f"/investigations/{i}") for i in ids]
    for _ in range(3):
        assert get_raw("/investigations") == first
        assert [get_raw(f"/investigations/{i}") for i in ids] == details
        assert json.loads(get_raw("/investigations")[1]) == json.loads(first[1])


# ------------------------------------- 17 cross-investigation C4 (synthetic)
def test_cross_investigation_c4_is_preserved_but_never_merges(tmp_path, monkeypatch):
    write_scenario(
        tmp_path,
        monkeypatch,
        {
            "events": [
                ssh_event("a-fail", 0, account="user-a", ip="203.0.113.7"),
                ssh_event("b-fail", 60, account="user-b", ip="203.0.113.7"),
                created_event("a-create", 300, "user-a"),
            ]
        },
    )
    status, listing = get("/investigations")
    assert status == 200 and listing["count"] == 2
    by_events = {tuple(i["event_ids"]): i for i in listing["investigations"]}
    a_summary = by_events[("a-fail", "a-create")]
    b_summary = by_events[("b-fail",)]
    assert a_summary["rule_ids"] == ["C2"]  # C4 is not an intra-investigation link
    assert a_summary["related_context_link_count"] == 1
    assert b_summary["related_context_link_count"] == 1

    _, a_detail = get(f"/investigations/{a_summary['investigation_id']}")
    _, b_detail = get(f"/investigations/{b_summary['investigation_id']}")
    (a_ctx,) = a_detail["related_context_links"]
    (b_ctx,) = b_detail["related_context_links"]

    for ctx, other in ((a_ctx, b_detail), (b_ctx, a_detail)):
        assert ctx["link"]["rule_id"] == "C4"
        assert ctx["link"]["strength"] == "MODERATE"
        assert ctx["link"]["merges_investigation"] is False
        assert ctx["merge_outcome"] == "not_merged_by_design"
        assert ctx["other_investigation_id"] == other["investigation_id"]
    assert (a_ctx["this_event_id"], a_ctx["other_event_id"]) == ("a-fail", "b-fail")
    assert (b_ctx["this_event_id"], b_ctx["other_event_id"]) == ("b-fail", "a-fail")
    assert "b-fail" not in a_detail["event_ids"] and "a-fail" not in b_detail["event_ids"]
    assert all(l["rule_id"] != "C4" for l in a_detail["links"] + b_detail["links"])


def test_cap_limited_merging_rule_is_not_reported_as_non_merging_by_design(
    tmp_path, monkeypatch
):
    # 21 same-account failed-SSH events one second apart: the engine's size cap
    # (20) stops the last event joining, although C3 would normally merge it.
    events = [ssh_event(f"e{i:02d}", i) for i in range(21)]
    write_scenario(tmp_path, monkeypatch, {"events": events})

    status, listing = get("/investigations")
    assert status == 200
    assert sorted(i["event_count"] for i in listing["investigations"]) == [1, 20]
    assert all(i["warning_count"] > 0 for i in listing["investigations"])

    seen = {}
    for summary in listing["investigations"]:
        _, detail = get(f"/investigations/{summary['investigation_id']}")
        assert {w["code"] for w in detail["warnings"]} == {"SIZE_CAP"}
        for ctx in detail["related_context_links"]:
            seen.setdefault(ctx["link"]["rule_id"], set()).add(
                (ctx["merge_outcome"], ctx["link"]["merges_investigation"])
            )

    # Same cross-investigation representation, two different meanings.
    assert seen["C3"] == {("not_merged_cap_limited", True)}
    assert seen["C4"] == {("not_merged_by_design", False)}


# ------------------------------------------------- architecture / contract
def test_openapi_documents_both_endpoints_and_keeps_existing_ones():
    status, spec = get("/openapi.json")
    assert status == 200
    paths = spec["paths"]
    assert "/investigations" in paths
    assert "/investigations/{investigation_id}" in paths
    for existing in ("/", "/health", "/alerts", "/incidents", "/triage/{incident_id}"):
        assert existing in paths
    assert set(paths["/investigations"]) == {"get"}
    assert set(paths["/investigations/{investigation_id}"]) == {"get"}


def test_main_py_only_registers_the_router():
    source = (REPO_ROOT / "backend" / "app" / "main.py").read_text()
    assert "include_router(investigations_router)" in source
    for forbidden in ("correlate", "load_events_from_scenario", "correlation_lab_scenario",
                      "backend.app.correlation"):
        assert forbidden not in source


def test_correlation_package_stays_independent_of_the_api_layer():
    package = REPO_ROOT / "backend" / "app" / "correlation"
    for module in package.glob("*.py"):
        source = module.read_text()
        for forbidden in ("fastapi", "pydantic", "starlette", "investigations_api"):
            assert forbidden not in source, f"{module.name} mentions {forbidden}"


def test_responses_do_not_leak_python_representations():
    status, raw = get_raw("/investigations")
    assert status == 200
    text = raw.decode()
    json.loads(text)  # valid JSON
    for marker in ("Strength.", "EventType.", "GapReason.", "datetime.", "timedelta(", "<"):
        assert marker not in text
