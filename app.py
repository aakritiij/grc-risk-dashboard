# app.py — Log ingestion + IOC analysis + AI insights stored in risk records
import os
import re
import uuid
import importlib.util
import sys
from typing import Dict, Any

# --- Load Helpers Dynamically ---
def load_module_from_path(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

BASE_DIR = os.path.dirname(__file__)
HELPERS_PATH = os.path.join(BASE_DIR, "src", "grc_risk_dashboard", "helpers.py")
AI_HELPER_PATH = os.path.join(BASE_DIR, "src", "ai_helper.py")

helpers = load_module_from_path("helpers", HELPERS_PATH)
ai_helper = load_module_from_path("ai_helper", AI_HELPER_PATH)

load_df = helpers.load_df
save_record = helpers.save_record
score_risk = helpers.score_risk
build_matrix = helpers.build_matrix
from src.ai_helper import predict_attack_and_mitigation

# --- Streamlit + Core Imports ---
import streamlit as st
import pandas as pd
import requests
import plotly.graph_objects as go

st.set_page_config(page_title="🛡️ GRC Risk Dashboard", layout="wide")

# ----------------------------
# 🧩 Authentication
# ----------------------------
VALID_USERNAME = "admin"
VALID_PASSWORD = "secure120"

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown(
        """
        <style>
        .block-container {
            max-width: 700px;
            margin: auto;
            padding-top: 5rem;
        }
        .login-box {
            background-color: #11141B;
            padding: 2.2rem;
            border-radius: 15px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.25);
            border: 1px solid rgba(255,255,255,0.1);
        }
        .login-title {
            text-align:center;
            color:#E4E8F0;
            font-size:1.8rem;
            font-weight:700;
            margin-bottom:1rem;
        }
        .demo-box {
            background-color: #1E2B3A;
            color:#B9C8D8;
            border-left:4px solid #2F80ED;
            padding:1rem;
            border-radius:8px;
            margin-bottom:1rem;
            font-size:0.95rem;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div class='login-box'>", unsafe_allow_html=True)
    st.markdown("<div class='login-title'>🔐 GRC Dashboard Login</div>", unsafe_allow_html=True)

    st.markdown(
        """
        <div class='demo-box'>
            👤 <b>Demo Credentials</b><br>
            Username: <b>admin</b><br>
            Password: <b>secure120</b>
        </div>
        """,
        unsafe_allow_html=True
    )

    username = st.text_input("Username", placeholder="Enter your username")
    password = st.text_input("Password", placeholder="Enter your password", type="password")

    if st.button("Login"):
        if username == VALID_USERNAME and password == VALID_PASSWORD:
            st.session_state.authenticated = True
            st.success("✅ Login successful! Loading dashboard...")
            st.rerun()
        else:
            st.error("❌ Invalid username or password.")
    st.stop()

# ----------------------------
# 🧠 Dashboard Main Area
# ----------------------------
st.title("🛡️ GRC Risk Dashboard (Automated Log Analysis)")

if st.sidebar.button("🚪 Logout"):
    st.session_state.authenticated = False
    st.rerun()

st.sidebar.info("Upload logs to auto-detect risks. Add ABUSEIPDB key in Secrets for live reputation checks.")

# -----------------------
# Helper Functions
# -----------------------
def extract_iocs(text: str) -> Dict[str, list]:
    """Extract common IOCs from text."""
    import re
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    urls = re.findall(r'(https?://[^\s,;]+)', text)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text)
    domains = [re.split(r'https?://', u)[-1].split('/')[0] for u in urls if "://" in u]
    return {
        "IPs": sorted(set(ips)),
        "URLs": sorted(set(urls)),
        "Domains": sorted(set(domains)),
        "Hashes": sorted(set(hashes)),
        "Emails": sorted(set(emails))
    }

def check_abuseipdb(ip: str, api_key: str):
    """Query AbuseIPDB for IP reputation."""
    if not api_key:
        return {"ip": ip, "error": "no_api_key"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {"ip": ip, "abuseConfidenceScore": int(data.get("abuseConfidenceScore", 0))}
        return {"ip": ip, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def map_score_to_li_impact(score: int):
    """Convert abuse score to likelihood and impact."""
    if score >= 80: return 5, 5
    elif score >= 60: return 4, 4
    elif score >= 40: return 3, 3
    elif score >= 20: return 2, 2
    else: return 1, 1

def create_risk_record(ioc_type, ioc_value, snippet, likelihood, impact):
    rid = str(uuid.uuid4())
    risk_score = score_risk(likelihood, impact)
    return {
        "risk_id": rid,
        "risk_name": f"{ioc_type}: {ioc_value}",
        "risk_description": snippet[:400],
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": risk_score,
        "owner": "AutoDetector",
        "attack_type": "",
        "mitigation": "",
        "timestamp": pd.Timestamp.now()
    }

# -----------------------
# Upload & Auto Analysis
# -----------------------
st.markdown("### 📁 Step 1: Upload your log file to detect risks automatically")
uploaded_file = st.file_uploader("Supported formats: .txt, .log, .csv", type=["txt", "log", "csv"])
ABUSEIPDB_KEY = st.secrets.get("ABUSEIPDB_API_KEY", None)

if uploaded_file:
    content = uploaded_file.read().decode("utf-8", errors="ignore")
    st.info(f"Processing **{uploaded_file.name}**...")
    iocs = extract_iocs(content)

    st.markdown("#### Extracted Indicators of Compromise (IOCs)")
    cols = st.columns(5)
    for i, k in enumerate(iocs.keys()):
        with cols[i]:
            st.metric(label=k, value=len(iocs[k]))
    st.divider()

    with st.expander("🔍 View extracted IOC details"):
        for k, vals in iocs.items():
            st.write(f"**{k}** ({len(vals)})")
            if vals: st.code("\n".join(vals))

    # AbuseIPDB Reputation
    ip_results = []
    if iocs["IPs"]:
        st.subheader("🌐 IP Reputation Check (AbuseIPDB)")
        if not ABUSEIPDB_KEY:
            st.warning("No API key set. Add ABUSEIPDB_API_KEY in Streamlit secrets.")
        else:
            progress = st.progress(0)
            for idx, ip in enumerate(iocs["IPs"], 1):
                ip_results.append(check_abuseipdb(ip, ABUSEIPDB_KEY))
                progress.progress(int((idx / len(iocs['IPs'])) * 100))
            progress.empty()
            df_ip = pd.DataFrame(ip_results)
            st.dataframe(df_ip, use_container_width=True)

    st.divider()
    st.markdown("### ✅ Step 2: Select IOCs to save as risks")
    to_save = []
    for t in iocs.keys():
        chosen = st.multiselect(f"Select {t} to include", options=iocs[t], key=f"choose_{t}")
        for val in chosen:
            to_save.append((t, val))

    if st.button("💾 Save Selected IOCs"):
        if not to_save:
            st.warning("Please select at least one IOC to save.")
        else:
            saved_count = 0
            for ioc_type, ioc_value in to_save:
                pos = content.find(ioc_value)
                snippet = content[max(0, pos - 120): min(len(content), pos + 120)] if pos != -1 else f"Detected {ioc_type} {ioc_value}"
                score = 50
                if ioc_type == "IPs":
                    res = next((r for r in ip_results if r.get("ip") == ioc_value and "abuseConfidenceScore" in r), {})
                    score = int(res.get("abuseConfidenceScore", 50))
                likelihood, impact = map_score_to_li_impact(score)

                # AI Insights
                try:
                    mitigation_info = predict_attack_and_mitigation(ioc_value, ioc_type, score, snippet)
                    import re
                    attack_match = re.search(r"Attack Type:\s*\*\*(.*?)\*\*", mitigation_info)
                    attack_type = attack_match.group(1) if attack_match else "Unknown"
                    mitigations = [line.strip("-• ").strip() for line in mitigation_info.split("\n") if line.strip().startswith("-")]
                    mitigation_text = "; ".join(mitigations[:3]) if mitigations else "N/A"
                except Exception as e:
                    st.sidebar.warning(f"AI unavailable: {e}")
                    attack_type, mitigation_text = "N/A", "N/A"

                record = create_risk_record(ioc_type, ioc_value, snippet, likelihood, impact)
                record["attack_type"], record["mitigation"] = attack_type, mitigation_text
                save_record(record)
                saved_count += 1

            st.success(f"✅ Saved {saved_count} IOCs as risks.")
            st.experimental_rerun()

# -----------------------
# Display Saved Risks + Heatmap
# -----------------------
df = load_df()
st.markdown("---")
st.subheader("📋 Saved Risks")

if not df.empty:
    expected_cols = ["risk_name", "attack_type", "likelihood", "impact", "risk_score", "mitigation", "owner", "timestamp"]
    cols = [c for c in expected_cols if c in df.columns] + [c for c in df.columns if c not in expected_cols]
    st.dataframe(df[cols], use_container_width=True)
    st.download_button("📥 Download Risk Data", df.to_csv(index=False).encode(), "risks.csv", "text/csv")

    # 🔥 Risk Heatmap
    st.markdown("### 🔥 Risk Matrix Visualization")
    matrix = build_matrix(df)
    numeric_matrix = pd.DataFrame(matrix).apply(pd.to_numeric, errors="coerce").fillna(0)

    fig = go.Figure(
        data=go.Heatmap(
            z=numeric_matrix,
            x=[1, 2, 3, 4, 5],
            y=[5, 4, 3, 2, 1],
            colorscale=[[0.0, "#00C896"], [0.5, "#FFCE54"], [1.0, "#E74C3C"]],
            hovertemplate="<b>Likelihood:</b> %{x}<br><b>Impact:</b> %{y}<br><b>Risks:</b> %{z}<extra></extra>",
            showscale=True,
            colorbar_title="Risk Level"
        )
    )
    fig.update_layout(
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        width=600, height=500,
        margin=dict(l=50, r=50, t=60, b=60),
        title=dict(text="📊 Organizational Risk Matrix", font=dict(size=18, color="#E6E9F0"), x=0.5)
    )
    st.plotly_chart(fig, use_container_width=False)

else:
    st.warning("No risks logged yet. Upload logs to auto-generate risks.")
