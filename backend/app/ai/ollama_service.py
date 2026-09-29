import json
import urllib.request


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL = "llama3.2:3b"


def generate_ai_summary(incident, triage_result):
    prompt = f"""
You are assisting a SOC analyst.

Analyze only the evidence provided below.
Do not invent indicators, users, hosts, processes, or attack activity.

INCIDENT:
{json.dumps(incident, indent=2)}

DETERMINISTIC TRIAGE:
{json.dumps(triage_result, indent=2)}

Produce a concise analyst assessment containing:

1. Summary
2. Evidence
3. MITRE ATT&CK context
4. Recommended analyst actions
5. Final assessment

Important:
- Distinguish observed facts from interpretation.
- If authorized_test is true, explicitly state that this was an
  authorized security validation exercise.
- Do not claim compromise unless the evidence supports it.
- Do not automatically close or remediate the incident.
- Never state that a host, account, or environment is uncompromised
  unless the supplied evidence explicitly proves that conclusion.
- Absence of a successful authentication does not prove absence of compromise.
- When evidence is insufficient, use language such as
  "No successful authentication was observed in the supplied evidence."
- Never invent remediation that has already occurred.
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    request = urllib.request.Request(
        OLLAMA_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(request, timeout=120) as response:
        result = json.loads(response.read().decode("utf-8"))

    return result["response"]