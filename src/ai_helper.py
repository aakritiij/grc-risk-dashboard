import random
import json
import os
import openai

# --- Fallback suggestions (used if AI API fails or for offline mode) ---
RISK_MITIGATION_SUGGESTIONS = {
    "data breach": [
        "Implement strong encryption (AES-256) for data at rest and in transit.",
        "Conduct quarterly data access audits.",
        "Use Data Loss Prevention (DLP) systems to monitor data exfiltration."
    ],
    "phishing": [
        "Conduct employee awareness training every quarter.",
        "Implement an advanced email filtering system.",
        "Enable multi-factor authentication (MFA) for all users."
    ],
    "ransomware": [
        "Maintain offline backups of critical systems.",
        "Regularly patch and update all endpoints.",
        "Deploy endpoint detection and response (EDR) solutions."
    ],
    "insider threat": [
        "Implement least-privilege access control.",
        "Use behavioral monitoring and anomaly detection tools.",
        "Establish strict offboarding and access revocation processes."
    ],
    "system failure": [
        "Implement redundant failover systems.",
        "Regularly test disaster recovery plans.",
        "Use uptime monitoring and alerting tools."
    ],
}

def get_mitigation_suggestions(risk_description: str) -> list[str]:
    """Returns fallback mitigation suggestions based on risk keywords."""
    desc = risk_description.lower()
    for keyword, suggestions in RISK_MITIGATION_SUGGESTIONS.items():
        if keyword in desc:
            return suggestions
    fallback = [
        "Perform regular risk assessments.",
        "Implement least-privilege principles.",
        "Ensure incident response plans are up to date.",
        "Enable continuous monitoring for unusual activity.",
    ]
    return random.sample(fallback, 3)

# --- Main AI predictor ---
def predict_attack_and_mitigation(ioc_value: str, ioc_type: str, abuse_score: int, context: str = "") -> str:
    """
    Uses OpenAI to predict attack category and suggest mitigations.
    Falls back to keyword-based suggestions if AI API is not configured.
    """
    openai.api_key = os.getenv("OPENAI_API_KEY")

    # fallback if no API key
    if not openai.api_key:
        suggestions = get_mitigation_suggestions(context)
        return f"⚙️ [Offline Mode]\nAttack Type: General Threat\nMitigations:\n- " + "\n- ".join(suggestions)

    prompt = f"""
    You are a cybersecurity analyst. Analyze the following IOC data and provide structured output.

    IOC Type: {ioc_type}
    IOC Value: {ioc_value}
    Abuse Confidence Score: {abuse_score}
    Context: {context}

    Predict:
    1. The most likely attack category.
    2. Three clear, actionable mitigation strategies.

    Return output as JSON like:
    {{
        "attack_category": "<attack type>",
        "mitigations": ["<mitigation 1>", "<mitigation 2>", "<mitigation 3>"]
    }}
    """

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=250,
        )

        raw_output = response.choices[0].message["content"]

        # Try to parse JSON from the model output
        try:
            parsed = json.loads(raw_output)
            attack_type = parsed.get("attack_category", "Unknown Threat")
            mitigations = parsed.get("mitigations", [])
            formatted = f"🧠 Predicted Attack Type: **{attack_type}**\n\n"
            formatted += "🔧 Recommended Mitigations:\n" + "\n".join([f"- {m}" for m in mitigations])
            return formatted
        except Exception:
            # fallback: show raw model text if not valid JSON
            return f"AI Response:\n{raw_output}"

    except Exception as e:
        suggestions = get_mitigation_suggestions(context)
        return f"⚠️ AI Error: {e}\nFallback Mitigations:\n- " + "\n- ".join(suggestions)
