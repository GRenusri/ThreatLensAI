import streamlit as st
import requests

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="ThreatLens AI",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ThreatLens AI")
st.caption("AI-Assisted SOC Incident Triage")

# -----------------------------------
# Load incidents from ThreatLens API
# -----------------------------------

try:
    response = requests.get(
        f"{API_URL}/incidents",
        timeout=10
    )
    response.raise_for_status()
    incident_data = response.json()

except requests.RequestException as error:
    st.error(f"Unable to connect to ThreatLens API: {error}")
    st.stop()


incidents = incident_data["incidents"]

# -----------------------------------
# Incident overview
# -----------------------------------

st.subheader("SOC Incident Queue")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric("Available Incidents", len(incidents))

with col2:
    medium_count = sum(
        1 for incident in incidents
        if incident.get("severity") == "Medium"
    )
    st.metric("Medium Severity", medium_count)

with col3:
    resolved_count = sum(
        1 for incident in incidents
        if incident.get("status") == "Resolved"
    )
    st.metric("Resolved", resolved_count)


st.divider()

# -----------------------------------
# Incident selection
# -----------------------------------

incident_options = {
    f"Incident {incident['incident_id']} — {incident['title']}": incident
    for incident in incidents
}

selected_label = st.selectbox(
    "Select an incident for investigation",
    incident_options.keys()
)

selected_incident = incident_options[selected_label]
incident_id = selected_incident["incident_id"]


# -----------------------------------
# Incident details
# -----------------------------------

st.subheader(selected_incident["title"])

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Severity",
        selected_incident.get("severity", "Unknown")
    )

with col2:
    st.metric(
        "Status",
        selected_incident.get("status", "Unknown")
    )

with col3:
    st.metric(
        "Host",
        selected_incident.get("host", "Unknown")
    )


st.write(
    "**Target Account:**",
    selected_incident.get("target_account", "N/A")
)

st.write(
    "**MITRE ATT&CK:**",
    f"{selected_incident.get('technique', 'N/A')} — "
    f"{selected_incident.get('technique_name', 'N/A')}"
)

st.write(
    "**Tactic:**",
    selected_incident.get("tactic", "N/A")
)

st.divider()

# -----------------------------------
# Deterministic triage
# -----------------------------------

st.subheader("Deterministic Triage")

try:
    triage_response = requests.post(
        f"{API_URL}/triage/{incident_id}",
        timeout=10
    )
    triage_response.raise_for_status()
    triage = triage_response.json()

    st.metric(
        "ThreatLens Risk Score",
        f"{triage['risk_score']} / 100"
    )

    st.write("**Findings**")

    for finding in triage["findings"]:
        st.write(f"• {finding}")

    st.write("**Recommended Analyst Actions**")

    for action in triage["recommended_actions"]:
        st.write(f"• {action}")

    if triage["analyst_review_required"]:
        st.info("Human analyst review required.")

except requests.RequestException as error:
    st.error(f"Unable to retrieve deterministic triage: {error}")


st.divider()

# -----------------------------------
# AI-assisted analysis
# -----------------------------------

st.subheader("AI-Assisted Analysis")

st.caption(
    "Local LLM analysis is advisory and does not replace analyst judgment."
)

if st.button(
    "Run AI-Assisted Analysis",
    type="primary"
):

    with st.spinner(
        "ThreatLens is analyzing the incident..."
    ):

        try:
            ai_response = requests.post(
                f"{API_URL}/triage/{incident_id}/ai",
                timeout=120
            )

            ai_response.raise_for_status()
            ai_result = ai_response.json()

            st.markdown(
                ai_result["ai_analyst_summary"]
            )

            validation = ai_result[
                "ai_output_validation"
            ]

            st.subheader("AI Output Validation")

            if validation["validation_passed"]:
                st.success(
                    "AI output passed the configured deterministic validation checks."
                )

            else:
                st.warning(
                    "AI output requires additional analyst review."
                )

                for warning in validation["warnings"]:
                    st.write(f"⚠️ {warning}")

            st.info(
                "Human review is required before any incident decision or remediation."
            )

        except requests.RequestException as error:
            st.error(
                f"AI analysis failed: {error}"
            )