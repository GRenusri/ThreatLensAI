# ThreatLens Deterministic Triage Validation

## Validation Results

### Incident 1 - New Local User Account Created
- MITRE ATT&CK: T1136.001 - Local Account
- Risk Score: 40/100
- Result: PASS
- ThreatLens identified the new account creation and generated account-validation and privilege-review actions.

### Incident 3 - User Added to Sudo Group
- MITRE ATT&CK: T1098.007 - Additional Local or Domain Groups
- Risk Score: 50/100
- Result: PASS
- ThreatLens identified the sudo-group privilege change and generated privilege-validation and subsequent-activity review actions.

### Incident 4 - Repeated Failed SSH Authentication
- MITRE ATT&CK: T1110.001 - Password Guessing
- Risk Score: 35/100
- Result: PASS
- ThreatLens identified three failed SSH authentication attempts and correctly stated that no successful authentication was observed in the supplied evidence.

## Risk Scoring

The ThreatLens risk scores are custom deterministic lab heuristics and are not Microsoft Sentinel risk scores or an industry-standard scoring system.

- Medium severity baseline: +20
- Local account creation: +20
- Sudo-group privilege change: +30
- Three or more failed SSH authentication attempts: +15

## Human Review

All triage results set:

`analyst_review_required = true`

ThreatLens recommendations are intended to assist, not replace, analyst investigation and decision-making.

## AI Validation Findings

### Incident 1 - New Local User Account

The local LLM correctly identified the account creation, MITRE ATT&CK
mapping, authorized-test context, and recommended analyst actions.

However, the AI stated that no successful authentication was observed.
Authentication evidence was not part of this incident's supplied evidence,
so this conclusion was unsupported.

### Incident 4 - Repeated Failed SSH Authentication

The local LLM correctly identified the repeated SSH failures and authorized
security-test context.

However, an earlier response stated that there was no evidence of host
compromise. The supplied SSH evidence was not sufficient to establish the
overall compromise state of the host.

### Design Decision

ThreatLens treats LLM-generated analysis as advisory rather than authoritative.

Deterministic triage remains the trusted source for structured findings and
risk scoring. AI-generated conclusions require validation before presentation
to the analyst, and final incident decisions require human review.

### Incident 3 - Sudo Group Privilege Change

The local LLM correctly identified the sudo-group privilege change,
MITRE ATT&CK T1098.007 context, authorized security-validation status,
and appropriate analyst investigation actions.

The response did not claim that unauthorized access or compromise had
occurred.

### Incident 4 - Guardrail Retest

After strengthening the AI instructions, the repeated failed SSH
authentication test was executed again.

The AI correctly limited its final assessment to the supplied evidence
and stated that no remediation or compromise conclusion could be drawn
from that evidence.

Result: PASS with human review required.

### AI Output Validator Test

The AI output validator was tested against Incident 1
(New Local User Account Created).

The LLM introduced an authentication-related conclusion even though
authentication was not the primary evidence represented by this incident.

ThreatLens detected the unsupported context and returned:

- validation_passed: false
- requires_human_review: true
- Warning: Authentication conclusion may not be supported for this incident.

Result: PASS

This demonstrates that ThreatLens does not automatically trust
LLM-generated security conclusions. AI output is checked by deterministic
validation logic before analyst review.

### AI Output Validator Retest

After removing irrelevant authentication data from the account-creation
incident, the LLM no longer generated the previous successful-authentication
conclusion.

However, the LLM generated another unsupported decision:

"No further action is required at this time."

The ThreatLens output validator detected this statement and returned:

- validation_passed: false
- requires_human_review: true
- Warning: Potential unsupported action conclusion detected

Result: PASS

This test also demonstrated a limitation of phrase-based output validation:
LLMs can express unsupported conclusions using many different forms of
natural language. ThreatLens therefore treats deterministic validation as
an additional guardrail rather than proof that AI output is factually safe.
Human analyst review remains mandatory.