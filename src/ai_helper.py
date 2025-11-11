import random

# Mock AI-based suggestions (for presentation & resume projects)
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
    """
    Returns a list of mitigation suggestions based on keywords found in the risk description.
    If no direct match is found, returns general best-practice mitigations.
    """
    desc = risk_description.lower()
    for keyword, suggestions in RISK_MITIGATION_SUGGESTIONS.items():
        if keyword in desc:
            return suggestions

    # Default fallback suggestions
    fallback = [
        "Perform regular risk assessments.",
        "Implement least-privilege principles.",
        "Ensure incident response plans are up to date.",
        "Enable continuous monitoring for unusual activity.",
    ]
    return random.sample(fallback, 3)

import openai

def predict_attack_and_mitigation(ioc, ioc_type, abuse_score, context=""):
    prompt = f"""
    Given the following IOC details:
    - Type: {ioc_type}
    - Value: {ioc}
    - Abuse Confidence Score: {abuse_score}
    - Context: {context}

    Predict:
    1. The most likely attack category.
    2. Three specific mitigation steps.
    Format as JSON with keys: attack_category, mitigations.
    """

    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",  # or your available model
        messages=[{"role": "user", "content": prompt}],
        temperature=0.4
    )

    return response.choices[0].message["content"]

