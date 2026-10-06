from fastapi import FastAPI
import json
from pathlib import Path
from backend.app.Security.input_validator import validate_input
from backend.app.triage.triage_engine import triage_incident
from backend.app.ai.ollama_service import generate_ai_summary
from backend.app.ai.output_validator import validate_ai_output
from backend.app.investigations_api import router as investigations_router

app = FastAPI(
    title="ThreatLens AI",
    description="AI-Powered Security Triage Platform",
    version="0.1.0"
)

app.include_router(investigations_router)

@app.get("/")
def home():
    return {
        "project": "ThreatLens AI",
        "status": "running"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }
@app.get("/alerts")
def get_alerts():

    file_path = Path("backend/data/sample_alerts.json")

    with open(file_path, "r") as file:
        alerts = json.load(file)

    return {
        "count": len(alerts),
        "alerts": alerts
    }
@app.get("/validate")
def validate(prompt: str):
    return validate_input(prompt)
@app.get("/incidents")
def get_incidents():
    file_path = Path("backend/data/sentinel_incidents.json")

    with open(file_path, "r") as file:
        incidents = json.load(file)

    return {
        "count": len(incidents),
        "incidents": incidents
    }
@app.post("/triage/{incident_id}")
def triage(incident_id: int):
    file_path = Path("backend/data/sentinel_incidents.json")

    with open(file_path, "r") as file:
        incidents = json.load(file)

    for incident in incidents:
        if incident.get("incident_id") == incident_id:
            return triage_incident(incident)

    return {
        "error": "Incident not found"
    }
@app.post("/triage/{incident_id}/ai")
def ai_triage(incident_id: int):
    file_path = Path("backend/data/sentinel_incidents.json")

    with open(file_path, "r") as file:
        incidents = json.load(file)

    for incident in incidents:
        if incident.get("incident_id") == incident_id:
            triage_result = triage_incident(incident)

            ai_summary = generate_ai_summary(
                incident,
                triage_result
            )

            output_validation = validate_ai_output(
                ai_summary,
                incident
            )

            return {
                "incident": incident,
                "deterministic_triage": triage_result,
                "ai_analyst_summary": ai_summary,
                "ai_output_validation": output_validation,
                "human_review_required": True
            }

    return {
        "error": "Incident not found"
    }