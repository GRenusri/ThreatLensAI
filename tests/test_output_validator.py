from backend.app.ai.output_validator import validate_ai_output


def test_clean_ai_output_passes():
    incident = {
        "title": "Linux - Repeated Failed SSH Authentication"
    }

    ai_summary = """
    Three failed SSH authentication attempts were observed.
    No successful authentication was observed in the supplied evidence.
    Additional analyst investigation is recommended.
    """

    result = validate_ai_output(ai_summary, incident)

    assert result["validation_passed"] is True
    assert result["warnings"] == []
    assert result["requires_human_review"] is True


def test_unsupported_compromise_claim_is_flagged():
    incident = {
        "title": "Linux - User Added to Sudo Group"
    }

    ai_summary = """
    The account was added to the sudo group.
    There is no evidence of compromise.
    """

    result = validate_ai_output(ai_summary, incident)

    assert result["validation_passed"] is False
    assert len(result["warnings"]) >= 1
    assert any(
        "compromise conclusion" in warning
        for warning in result["warnings"]
    )


def test_unsupported_no_action_claim_is_flagged():
    incident = {
        "title": "Linux - New Local User Account Created"
    }

    ai_summary = """
    The account creation was observed during testing.
    No further action is required.
    """

    result = validate_ai_output(ai_summary, incident)

    assert result["validation_passed"] is False
    assert any(
        "action conclusion" in warning
        for warning in result["warnings"]
    )


def test_irrelevant_authentication_claim_is_flagged():
    incident = {
        "title": "Linux - New Local User Account Created"
    }

    ai_summary = """
    A new local account was created.
    No successful authentication was observed.
    """

    result = validate_ai_output(ai_summary, incident)

    assert result["validation_passed"] is False
    assert any(
        "Authentication conclusion" in warning
        for warning in result["warnings"]
    )