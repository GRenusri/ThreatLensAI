# 🛡️ ThreatLens AI

ThreatLens AI is an AI-assisted SOC incident triage project that combines
Microsoft Sentinel security detections, deterministic security analysis,
MITRE ATT&CK context, a local LLM, AI-output validation, and mandatory
human analyst review.

The project was built using a controlled Linux SOC lab connected to
Microsoft Sentinel.

## Project Goals

ThreatLens was designed to explore how AI can assist a SOC analyst without
allowing an LLM to become the authoritative source for security decisions.

The workflow separates:

- Security telemetry and detection
- Deterministic triage
- MITRE ATT&CK context
- AI-assisted interpretation
- AI-output validation
- Human analyst decision-making

## Architecture

```text
Ubuntu Linux Security Activity
        |
        v
Azure Arc + Azure Monitor Agent
        |
        v
Data Collection Rule
        |
        v
Log Analytics Workspace
        |
        v
Microsoft Sentinel
        |
        v
KQL Analytics Rules
        |
        v
Representative Incident Payloads
        |
        v
ThreatLens FastAPI Backend
        |
        +-------------------------+
        |                         |
        v                         v
Deterministic Triage        MITRE ATT&CK Context
        |                         |
        +------------+------------+
                     |
                     v
              Local Ollama LLM
              llama3.2:3b
                     |
                     v
              AI Output Validator
                     |
                     v
              Human Analyst Review
                     |
                     v
              Streamlit Dashboard