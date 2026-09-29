def triage_incident(incident):
    risk_score = 0
    findings = []
    recommended_actions = []

    # -------------------------
    # 1. Base severity scoring
    # -------------------------
    severity = incident.get("severity", "").lower()

    severity_scores = {
        "critical": 40,
        "high": 30,
        "medium": 20,
        "low": 10
    }

    risk_score += severity_scores.get(severity, 0)

    # -------------------------
    # 2. Common incident data
    # -------------------------
    title = incident.get("title", "")
    target_account = incident.get("target_account")
    technique = incident.get("technique")
    technique_name = incident.get("technique_name")

    # -------------------------
    # 3. Behavior-specific logic
    # -------------------------

    # New local account creation
    if title == "Linux - New Local User Account Created":
        risk_score += 20

        findings.append(
            f"New local Linux account '{target_account}' was created."
        )

        recommended_actions.append(
            "Validate whether the account creation was authorized."
        )

        recommended_actions.append(
            "Review the account's privileges and surrounding authentication activity."
        )

    # User added to sudo group
    elif title == "Linux - User Added to Sudo Group":
        risk_score += 30

        findings.append(
            f"Account '{target_account}' was added to the sudo group."
        )

        recommended_actions.append(
            "Validate whether the privilege change was authorized."
        )

        recommended_actions.append(
            "Review subsequent privileged activity performed by the account."
        )

    # Repeated failed SSH authentication
    elif title == "Linux - Repeated Failed SSH Authentication":
        failed_attempts = incident.get("failed_attempts", 0)

        if failed_attempts >= 3:
            risk_score += 15

            findings.append(
                f"{failed_attempts} failed SSH authentication attempts were detected."
            )

        if incident.get("successful_authentication"):
            risk_score += 35

            findings.append(
                "A successful authentication was observed after suspicious authentication activity."
            )

            recommended_actions.append(
                "Investigate the successful login and associated session immediately."
            )
        else:
            findings.append(
                "No successful authentication was observed in the supplied evidence."
            )

        recommended_actions.append(
            "Review the source IP and surrounding SSH authentication activity."
        )

    # -------------------------
    # 4. MITRE ATT&CK context
    # -------------------------
    if technique:
        findings.append(
            f"Activity maps to MITRE ATT&CK {technique} ({technique_name})."
        )

    # -------------------------
    # 5. Authorized-test context
    # -------------------------
    if incident.get("authorized_test"):
        findings.append(
            "Incident is marked as an authorized security validation exercise."
        )

        recommended_actions.append(
            "Document the validation result according to security testing procedures."
        )

    # -------------------------
    # 6. Final score
    # -------------------------
    risk_score = min(risk_score, 100)

    return {
        "incident_id": incident.get("incident_id"),
        "title": title,
        "risk_score": risk_score,
        "findings": findings,
        "recommended_actions": recommended_actions,
        "analyst_review_required": True
    }