def validate_ai_output(ai_summary, incident):
    warnings = []

    summary_lower = ai_summary.lower()
    title = incident.get("title", "")

    # Detect unsupported compromise conclusions
    unsupported_compromise_claims = [
        "no compromise",
        "not compromised",
        "uncompromised",
        "no evidence of compromise",
        "not indicative of a potential compromise",
        "not indicative of compromise",
        "no indication of compromise"
    ]

    for phrase in unsupported_compromise_claims:
        if phrase in summary_lower:
            warnings.append(
                f"Potential unsupported compromise conclusion detected: '{phrase}'"
            )

    # Detect unsupported decisions that no further action is required
    unsupported_action_claims = [
        "no further action is required",
        "no further action required",
        "no action is required",
        "no additional action is required"
    ]

    for phrase in unsupported_action_claims:
        if phrase in summary_lower:
            warnings.append(
                f"Potential unsupported action conclusion detected: '{phrase}'"
            )

    # Authentication conclusions should only appear when
    # authentication evidence is relevant to the incident
    authentication_incident = (
        title == "Linux - Repeated Failed SSH Authentication"
    )

    if not authentication_incident:
        authentication_claims = [
            "no successful authentication",
            "successful authentication was not observed",
            "absence of successful authentication"
        ]

        for phrase in authentication_claims:
            if phrase in summary_lower:
                warnings.append(
                    f"Authentication conclusion may not be supported for this incident: '{phrase}'"
                )

    return {
        "validation_passed": len(warnings) == 0,
        "warnings": warnings,
        "requires_human_review": True
    }