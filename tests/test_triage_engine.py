from backend.app.triage.triage_engine import triage_incident


def test_new_local_user_account():
    incident = {
        "incident_id": 1,
        "title": "Linux - New Local User Account Created",
        "severity": "Medium",
        "target_account": "sentinel-alert-test",
        "technique": "T1136.001",
        "technique_name": "Local Account",
        "authorized_test": True
    }

    result = triage_incident(incident)

    assert result["incident_id"] == 1
    assert result["risk_score"] == 40
    assert result["analyst_review_required"] is True
    assert any(
        "New local Linux account" in finding
        for finding in result["findings"]
    )
    assert any(
        "T1136.001" in finding
        for finding in result["findings"]
    )


def test_sudo_group_addition():
    incident = {
        "incident_id": 3,
        "title": "Linux - User Added to Sudo Group",
        "severity": "Medium",
        "target_account": "sudo-detection-test",
        "technique": "T1098.007",
        "technique_name": "Additional Local or Domain Groups",
        "authorized_test": True
    }

    result = triage_incident(incident)

    assert result["incident_id"] == 3
    assert result["risk_score"] == 50
    assert result["analyst_review_required"] is True
    assert any(
        "sudo group" in finding
        for finding in result["findings"]
    )
    assert any(
        "T1098.007" in finding
        for finding in result["findings"]
    )


def test_failed_ssh_authentication():
    incident = {
        "incident_id": 4,
        "title": "Linux - Repeated Failed SSH Authentication",
        "severity": "Medium",
        "target_account": "fake-soc-user",
        "source_ip": "192.168.145.1",
        "failed_attempts": 3,
        "technique": "T1110.001",
        "technique_name": "Password Guessing",
        "authorized_test": True,
        "successful_authentication": False
    }

    result = triage_incident(incident)

    assert result["incident_id"] == 4
    assert result["risk_score"] == 35
    assert result["analyst_review_required"] is True
    assert any(
        "3 failed SSH authentication attempts" in finding
        for finding in result["findings"]
    )
    assert any(
        "No successful authentication was observed" in finding
        for finding in result["findings"]
    )
    assert any(
        "T1110.001" in finding
        for finding in result["findings"]
    )