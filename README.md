# 🛡️ ThreatLens AI

![ThreatLens CI](https://github.com/GRenusri/ThreatLensAI/actions/workflows/ci.yml/badge.svg)

ThreatLens AI is an AI-assisted SOC investigation and incident-triage project built around Microsoft Sentinel telemetry, KQL detections, deterministic security-event correlation, analyst-facing investigations, deterministic triage, local LLM interpretation, AI-output validation, and mandatory human review.

The project was developed in a controlled Linux SOC lab and demonstrates an end-to-end defensive workflow from security telemetry and detection through correlation, investigation, triage, and AI-assisted analysis.

> **Project boundary:** ThreatLens uses representative structured incident payloads and controlled correlation evidence derived from Microsoft Sentinel lab activity. Live Microsoft Sentinel API ingestion is not implemented.

---

## 🎯 What This Project Demonstrates

ThreatLens was built around one core principle:

> **Security evidence and deterministic logic establish the facts. AI helps interpret those facts. The analyst makes the decision.**

The project demonstrates hands-on work with:

- Microsoft Sentinel
- KQL detection engineering
- Linux security telemetry
- Security-event normalization
- Deterministic event correlation
- Investigation timelines
- FastAPI security APIs
- MITRE ATT&CK context
- Deterministic risk/triage logic
- Local LLM integration with Ollama
- AI-output guardrails
- Automated testing
- GitHub Actions CI
- Human-in-the-loop SOC analysis

---

## 🏗️ Architecture

```text
VMware Ubuntu (soc-linux-01)
        |
        v
Azure Arc
        |
        v
Azure Monitor Agent (AMA)
        |
        v
Data Collection Rule (DCR)
        |
        v
Log Analytics Workspace
        |
        v
Microsoft Sentinel
        |
        v
KQL Detection Logic
        |
        v
Controlled / Representative Security Events
        |
        v
Event Normalization
        |
        v
Deterministic Correlation Engine
        |
        v
Investigation Timeline
        |
        v
Investigation API
        |
        +----------------------+
        |                      |
        v                      v
Deterministic Triage      Analyst Investigation
        |
        v
MITRE ATT&CK Context
        |
        v
Local Ollama LLM
        |
        v
Deterministic AI Output Validation
        |
        v
Human Analyst Review
        |
        v
Streamlit SOC Dashboard
```

The correlation, triage, and validation layers are intentionally deterministic. The LLM does not determine whether events correlate, calculate the ThreatLens risk score, close incidents, or perform remediation.

---

## 🔎 Microsoft Sentinel Detection Engineering

Three custom KQL detection scenarios were implemented and validated using controlled Linux activity.

### 1. New Local User Account Created

Detects successful Linux local-account creation events recorded by `useradd`.

**MITRE ATT&CK:** T1136.001 — Create Account: Local Account

```kusto
Syslog
| where Computer =~ "soc-linux-01"
| where Facility =~ "authpriv"
| where ProcessName =~ "useradd"
| where SyslogMessage startswith "new user:"
| parse SyslogMessage with "new user: name=" NewAccount ", UID=" UID ", GID=" GID ", home=" HomeDirectory ", shell=" Shell ", from=" Source
| project TimeGenerated, Computer, NewAccount, UID, GID, HomeDirectory, Shell, Source, SyslogMessage
```

Controlled validation generated matching account-creation telemetry.

![Sentinel account creation detection](docs/screenshots/01-sentinel-account-creation-detection.png)

### 2. User Added to Sudo Group

Detects Linux accounts added to the `sudo` group.

**MITRE ATT&CK:** T1098.007 — Additional Local or Domain Groups

```kusto
Syslog
| where Computer =~ "soc-linux-01"
| where Facility =~ "authpriv"
| where ProcessName =~ "usermod"
| where SyslogMessage startswith "add '"
| where SyslogMessage contains "to group 'sudo'"
| parse SyslogMessage with "add '" TargetAccount "' to group 'sudo'"
| project TimeGenerated, Computer, TargetAccount, ProcessName, SyslogMessage
```

Controlled testing generated matching `usermod` telemetry.

![Sentinel sudo group detection](docs/screenshots/02-sentinel-sudo-group-detection.png)

### 3. Repeated Failed SSH Authentication

Detects repeated failed SSH authentication attempts against an invalid Linux account.

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

```kusto
Syslog
| where Computer =~ "soc-linux-01"
| where ProcessName =~ "sshd-session"
| where SyslogMessage startswith "Failed password for invalid user"
| parse SyslogMessage with "Failed password for invalid user " TargetAccount " from " SourceIP " port " SourcePort:int " ssh2"
| summarize
    FailedAttempts = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Computer, TargetAccount, SourceIP
| where FailedAttempts >= 3
| extend TimeGenerated = LastAttempt
```

Controlled validation confirmed repeated failed SSH activity from the lab environment.

![Sentinel failed SSH detection](docs/screenshots/03-sentinel-failed-ssh-detection.png)

---

## 🔗 Deterministic Security-Event Correlation

ThreatLens includes a deterministic correlation engine that groups related security events into analyst investigations without relying on an LLM to decide whether events are related.

The controlled correlation scenario contains:

```text
Failed SSH attempts
        ↓
Account creation
        ↓
Sudo-group addition
```

A separate decoy account-creation event is included as a false-correlation control.

### Correlation Rules

| Rule | Relationship | Strength | Investigation Merge |
|---|---|---|---|
| C1 | Account creation → later sudo addition for the same account and host | STRONG | Yes |
| C2 | Failed SSH invalid-user event → later account creation for the same account and host | MODERATE | Yes |
| C3 | Recurrence of the same detection for the same discriminating account and host | STRONG | Yes |
| C4 | Shared usable source IP across failed SSH events | MODERATE | No |

C4 is intentionally contextual. A shared source IP can establish useful investigative context without being strong enough by itself to merge otherwise separate investigations.

### Correlation Safety Boundaries

The engine deliberately fails closed in ambiguous situations:

- Host alone does not merge events.
- Time proximity alone does not merge events.
- Missing values are not treated as matches.
- Equal timestamps do not satisfy ordered C1/C2 relationships.
- Generic identities are not sufficient for C3 correlation.
- C4 never merges investigations.
- Correlation does not imply causation.
- Failed authentication does not imply successful access.
- The engine does not infer compromise.
- Actor identity is not inferred when telemetry does not establish it.
- MITRE ATT&CK techniques are preserved only when supported by evidence.

### Controlled Correlation Result

The primary controlled scenario correlates five related events:

```text
corr-ssh-001
corr-ssh-002
corr-ssh-003
corr-account-001
corr-sudo-001
```

into one deterministic investigation.

The separate event:

```text
corr-decoy-001
```

remains isolated.

This decoy event provides a deliberate negative control demonstrating that temporal proximity alone is not enough to correlate unrelated security activity.

Detailed evidence is preserved in:

```text
docs/correlation-lab-validation.md
```

---

## 🧭 Investigation API

ThreatLens exposes correlated investigations through FastAPI.

### List Investigations

```http
GET /investigations
```

Returns analyst-oriented investigation summaries including:

- Investigation ID
- Event IDs and event count
- First and last event timestamps
- Accounts
- Hosts
- Source IPs
- Correlation rule IDs
- Related-context count
- Warning/evidence-gap counts
- Analyst-review requirement

### Investigation Detail

```http
GET /investigations/{investigation_id}
```

Returns the detailed investigation including:

- Chronological timeline
- Correlation links
- Rule IDs
- Correlation strength
- Time differences
- Shared entities
- Correlation reasons and limitations
- Related-context links
- Evidence gaps
- Warnings
- Unavailable telemetry
- Analyst-review requirement

The API serializes deterministic correlation-engine results. It does not ask the LLM to construct or determine investigations.

Evidence-loading failures fail closed rather than returning a misleading empty investigation list.

Investigation IDs in this lab are deterministic and derived from investigation membership. They should not be interpreted as long-term production case identifiers.

---

## ⚙️ Deterministic Incident Triage

ThreatLens performs deterministic analysis before invoking the LLM.

The triage engine evaluates known incident fields and produces:

- A custom ThreatLens risk score
- Evidence-based findings
- MITRE ATT&CK context
- Recommended analyst actions
- Mandatory analyst-review status

Current representative scenarios produce:

| Incident | Scenario | ThreatLens Risk Score |
|---|---|---:|
| 1 | New Local User Account Created | 40 / 100 |
| 3 | User Added to Sudo Group | 50 / 100 |
| 4 | Repeated Failed SSH Authentication | 35 / 100 |

These scores are **custom deterministic lab heuristics**. They are not Microsoft Sentinel risk scores and are not presented as an industry-standard scoring system.

![ThreatLens deterministic triage](docs/screenshots/04-threatlens-deterministic-triage.png)

---

## 🤖 Local AI-Assisted Analysis

ThreatLens uses a locally running Ollama model:

```text
llama3.2:3b
```

The model receives structured incident information and deterministic triage results and produces an analyst-oriented assessment.

The AI is instructed not to invent indicators, users, hosts, processes, remediation results, or unsupported compromise conclusions.

AI output remains advisory.

![ThreatLens AI-assisted analysis](docs/screenshots/05-threatlens-ai-analysis-passed.png)

---

## 🛡️ AI Output Validation

LLM output is passed through an additional deterministic validator.

The current validator checks configured classes of unsupported statements, including:

- Unsupported conclusions that compromise did not occur
- Unsupported statements that no further action is required
- Authentication conclusions applied to incidents without authentication evidence

This component is intentionally described as a **guardrail**, not a complete hallucination detector.

Human review remains mandatory regardless of whether AI-output validation passes.

---

## 👨‍💻 Human-in-the-Loop Design

ThreatLens follows:

```text
Security Evidence
        ↓
Deterministic Analysis
        ↓
AI Interpretation
        ↓
Deterministic Output Validation
        ↓
Human Analyst
```

ThreatLens does not automatically:

- Declare an environment uncompromised
- Close Sentinel incidents
- Block accounts or IP addresses
- Perform remediation
- Change Sentinel incident severity

The analyst remains responsible for the final investigation decision.

---

## 🖥️ Streamlit SOC Dashboard

The Streamlit interface provides an analyst-facing view of the representative incident queue.

It displays:

- Incident metadata
- Severity and status
- Host and target account
- MITRE ATT&CK mapping
- Deterministic ThreatLens risk score
- Findings
- Recommended analyst actions
- Local AI-assisted analysis
- AI-output validation results
- Human-review requirement

---

## 🧪 Automated Testing

ThreatLens currently has **126 automated tests** covering the security-critical deterministic components and API boundary.

The suite includes tests for:

### Correlation Engine

- C1–C4 correlation semantics
- Correlation windows and boundaries
- Missing-value fail-closed behavior
- Generic-account safeguards
- Source-IP handling
- Investigation size/span caps
- Deterministic investigation IDs
- Timestamp normalization
- Decoy isolation
- Input-order independence
- Prevention of unsupported actor/authentication/compromise inference

### Investigation API

- Investigation summaries and details
- Timeline serialization
- C1–C4 preservation through the API
- C4 non-merging behavior
- Cross-investigation related context
- Deterministic responses
- Evidence error handling
- Unknown-investigation 404 behavior
- API path independence
- OpenAPI endpoint registration
- Separation between correlation and API layers

### Existing Security Components

- Input validation
- AI-output validation
- Deterministic triage scenarios

Run the complete test suite:

```powershell
python -m pytest tests -v -p no:cacheprovider
```

Validated local result:

```text
126 passed
```

---

## 🔄 GitHub Actions CI

GitHub Actions automatically executes the ThreatLens test suite on repository changes.

The workflow:

1. Checks out the repository
2. Sets up Python
3. Installs dependencies
4. Executes the complete pytest suite

The current Phase 2 implementation passes the complete **126-test suite** locally and in GitHub Actions.

![ThreatLens GitHub Actions tests](docs/screenshots/06-github-actions-tests-passed.png)

---

## 🔐 Input Validation

ThreatLens includes a basic input-validation component for user-supplied text.

Checks include:

- Empty input
- Maximum input length
- Configured common prompt-injection phrases
- Case-insensitive matching

This is a basic application-layer guardrail and is **not comprehensive prompt-injection protection**.

The `/validate` functionality is separate from the core representative Sentinel incident triage path.

---

## 🧰 Technology Stack

| Area | Technology |
|---|---|
| Lab Environment | VMware Workstation, Ubuntu Linux |
| Azure Connectivity | Azure Arc |
| Telemetry Collection | Azure Monitor Agent |
| Routing | Data Collection Rule |
| Log Platform | Log Analytics Workspace |
| SIEM | Microsoft Sentinel |
| Detection Language | KQL |
| Security Context | MITRE ATT&CK |
| Correlation | Python deterministic rules |
| Backend/API | Python, FastAPI |
| Local AI | Ollama, llama3.2:3b |
| Dashboard | Streamlit |
| Testing | pytest |
| CI | GitHub Actions |
| Version Control | Git, GitHub |

---

## 📁 Project Structure

```text
ThreatLensAI/
├── .github/
│   └── workflows/
│       └── ci.yml
├── backend/
│   ├── app/
│   │   ├── ai/
│   │   │   ├── ollama_service.py
│   │   │   └── output_validator.py
│   │   ├── correlation/
│   │   │   ├── __init__.py
│   │   │   ├── config.py
│   │   │   ├── engine.py
│   │   │   ├── models.py
│   │   │   └── normalization.py
│   │   ├── Security/
│   │   │   └── input_validator.py
│   │   ├── triage/
│   │   │   └── triage_engine.py
│   │   ├── investigations_api.py
│   │   └── main.py
│   └── data/
│       ├── correlation_lab_scenario.json
│       ├── sample_alerts.json
│       └── sentinel_incidents.json
├── docs/
│   ├── screenshots/
│   ├── correlation-lab-validation.md
│   └── triage-validation.md
├── tests/
│   ├── test_correlation_engine.py
│   ├── test_correlation_lab_scenario.py
│   ├── test_input_validator.py
│   ├── test_investigations_api.py
│   ├── test_output_validator.py
│   └── test_triage_engine.py
├── dashboard.py
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

---

## 🚀 Running ThreatLens Locally

### 1. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 3. Start Ollama

ThreatLens expects:

```text
llama3.2:3b
```

### 4. Start FastAPI

```powershell
uvicorn backend.app.main:app --reload
```

API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

Useful investigation endpoints:

```text
GET /investigations
GET /investigations/{investigation_id}
```

### 5. Start the Streamlit Dashboard

In another terminal:

```powershell
streamlit run dashboard.py
```

The dashboard is available at:

```text
http://localhost:8501
```

---

## 📊 Evidence Sources

ThreatLens currently uses two controlled data paths.

### Representative Incident Dataset

```text
backend/data/sentinel_incidents.json
```

Used by the existing representative incident-triage workflow.

### Controlled Correlation Scenario

```text
backend/data/correlation_lab_scenario.json
```

Used to validate deterministic multi-event correlation and investigation construction.

Both originate from controlled lab work. ThreatLens does **not** claim that the current application retrieves incidents through the live Microsoft Sentinel API.

---

## ⚠️ Current Limitations

ThreatLens is a lab/portfolio project, not a production SOC platform.

Current limitations include:

- No live Microsoft Sentinel API ingestion
- Representative/controlled JSON evidence is used by the application
- Risk scoring uses custom deterministic lab heuristics
- Correlation windows are configurable lab defaults, not claimed industry standards
- AI-output validation uses limited deterministic phrase/context checks
- Input validation is basic
- No production authentication/authorization layer
- No automated remediation or Sentinel incident closure
- Local Ollama availability is required for AI-assisted analysis

These limitations are documented deliberately so the project does not claim capabilities it has not implemented.

---

## 🔮 Next Steps

Potential production-oriented improvements include:

- Live Microsoft Sentinel API ingestion
- Production authentication and authorization
- Broader detection and telemetry coverage

These are future improvements and are **not implemented in the current version**.

---

## 📚 Validation Evidence

Correlation validation:

```text
docs/correlation-lab-validation.md
```

Triage and AI validation:

```text
docs/triage-validation.md
```

Additional screenshots are stored under:

```text
docs/screenshots/
```

---

## ⚖️ Lab Scope

All security activity was generated in a controlled lab environment for defensive security testing and learning.

ThreatLens is designed as an analyst-assistance workflow. Correlation establishes evidence relationships rather than causation, AI-generated content remains advisory, and human review is required before security decisions or remediation.