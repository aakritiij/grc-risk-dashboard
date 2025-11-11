# app.py — Log ingestion + IOC analysis replacement for manual risk form
from src.ai_helper import predict_attack_and_mitigation
import os
import re
import uuid
import importlib.util
import sys
from typing import Dict, Any

# --- robust import of helpers and ai_helper ---
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
try:
    ai_helper = load_module_from_path("ai_helper", AI_HELPER_PATH)
except Exception:
    ai_helper = None

load_df = helpers.load_df
save_record = helpers.save_record
score_risk = helpers.score_risk
build_matrix = helpers.build_matrix

# --- standard imports ---
import streamlit as st
import pandas as pd
import numpy as np
import requests
import plotly.graph_objects as go

st.set_page_config(page_title="GRC Risk Dashboard", layout="wide")
st.title("🛡️ GRC Risk Dashboard (Log Ingestion Mode)")

st.sidebar.info("Upload logs to auto-detect risks. Add ABUSEIPDB key in Secrets for live reputation checks.")

# -----------------------
# Helper functions
# -----------------------
def extract_iocs(text: str) -> Dict[str, list]:
    """Extract basic IOCs from raw log text."""
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    urls = re.findall(r'(https?://[^\s,;]+)', text)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', text)
    domains = []
    for u in urls:
        try:
            parts = re.split(r'https?://', u)[-1]
            dom = parts.split('/')[0]
            domains.append(dom)
        except Exception:
            continue
    return {
        "IPs": sorted(set(ips)),
        "URLs": sorted(set(urls)),
        "Domains": sorted(set(domains)),
        "Hashes": sorted(set(hashes)),
        "Emails": sorted(set(emails))
    }

def check_abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    """Query AbuseIPDB for IP reputation."""
    if not api_key:
        return {"ip": ip, "error": "no_api_key"}
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        r = requests.get(url, headers=headers, params=params, timeout=10)
        if r.status_code == 200:
            j = r.json().get("data", {})
            return {
                "ip": ip,
                "abuseConfidenceScore": int(j.get("abuseConfidenceScore", 0)),
                "countryCode": j.get("countryCode", ""),
                "isp": j.get("isp", ""),
                "domain": j.get("domain", "")
            }
        else:
            return {"ip": ip, "error": f"status_{r.status_code}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}

def map_score_to_li_impact(score: int) -> tuple:
    """Map 0–100 threat score to Likelihood/Impact scale."""
    if score >= 80:
        return 5, 5
    elif score >= 60:
        return 4, 4
    elif score >= 40:
        return 3, 3
    elif score >= 20:
        return 2, 2
    else:
        return 1, 1

def create_risk_record_from_ioc(ioc_type: str, ioc_value: str, context_snippet: str, likelihood: int, impact: int) -> dict:
    rid = str(uuid.uuid4())
    risk_score = score_risk(likelihood, impact)
    return {
        "risk_id": rid,
        "risk_name": f"{ioc_type}: {ioc_value}",
        "risk_description": context_snippet[:400],
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": risk_score,
        "risk_cell": f"{likelihood}x{impact}",
        "owner": "AutoDetector",
        "mitigation": "",
        "timestamp": pd.Timestamp.now()
    }

# -----------------------
# Upload + IOC Analysis
# -----------------------
st.markdown("## 1) Upload logs to auto-detect risks")
uploaded_file = st.file_uploader("Upload log file (.txt, .log, .csv)", type=["txt", "log", "csv"])
ABUSEIPDB_KEY = st.secrets.get("ABUSEIPDB_API_KEY", None)

if uploaded_file:
    raw_bytes = uploaded_file.read()
    content = raw_bytes.decode("utf-8", errors="ignore")

    st.info(f"Processing {uploaded_file.name} ...")
    iocs = extract_iocs(content)

    # IOC Summary
    st.markdown("### Extracted IOCs summary")
    cols = st.columns(5)
    for i, k in enumerate(["IPs", "URLs", "Domains", "Hashes", "Emails"]):
        with cols[i]:
            st.metric(label=k, value=len(iocs.get(k, [])))
    st.markdown("---")

    with st.expander("Show extracted IOCs"):
        for k in ["IPs", "URLs", "Domains", "Hashes", "Emails"]:
            vals = iocs.get(k, [])
            st.write(f"**{k}** ({len(vals)})")
            if vals:
                st.code("\n".join(vals))

    # AbuseIPDB Reputation
    ip_results = []
    if iocs["IPs"]:
        st.markdown("### IP Reputation (AbuseIPDB)")
        if not ABUSEIPDB_KEY:
            st.warning("Add ABUSEIPDB_API_KEY in Streamlit secrets for reputation checks.")
        else:
            progress = st.progress(0)
            for idx, ip in enumerate(iocs["IPs"], 1):
                res = check_abuseipdb(ip, ABUSEIPDB_KEY)
                ip_results.append(res)
                progress.progress(int((idx / len(iocs["IPs"])) * 100))
            progress.empty()
            df_ip = pd.DataFrame(ip_results)
            st.dataframe(df_ip, use_container_width=True)
            try:
                st.bar_chart(df_ip.set_index("ip")["abuseConfidenceScore"])
            except Exception:
                pass

    # Select & Save IOCs as Risks
    st.markdown("---")
    st.markdown("## 2) Select which IOCs to convert into risks")
    to_save = []
    for t in ["IPs", "URLs", "Domains", "Hashes", "Emails"]:
        items = iocs.get(t, [])
        if items:
            chosen = st.multiselect(f"Select {t} to save as risks", options=items, key=f"choose_{t}")
            for val in chosen:
                to_save.append((t, val))

    if st.button("💾 Save selected IOCs as risks"):
        if not to_save:
            st.warning("Pick at least one IOC to save.")
        else:
            saved_count = 0
            for ioc_type, ioc_value in to_save:
                pos = content.find(ioc_value)
                start = max(0, pos - 120)
                end = min(len(content), pos + 120)
                snippet = content[start:end] if pos != -1 else f"Auto-detected {ioc_type} {ioc_value}"

                if ioc_type == "IPs":
                    score = None
                    for r in ip_results:
                        if r.get("ip") == ioc_value and "abuseConfidenceScore" in r:
                            score = int(r.get("abuseConfidenceScore", 0))
                            break
                    likelihood, impact = map_score_to_li_impact(score or 50)
                else:
                    likelihood, impact = 3, 3
                    score = 50

                record = create_risk_record_from_ioc(ioc_type, ioc_value, snippet, likelihood, impact)
                save_record(record)

                # --- AI Attack Prediction + Mitigation ---
                try:
                    mitigation_info = predict_attack_and_mitigation(ioc_value, ioc_type, score, snippet)
                    st.sidebar.markdown(f"**AI Insights for {ioc_value}:**")
                    st.sidebar.info(mitigation_info)
                except Exception as e:
                    st.sidebar.warning(f"AI suggestion unavailable: {e}")

                saved_count += 1

            st.success(f"✅ Saved {saved_count} IOCs as risk records.")
            st.experimental_rerun()

# -----------------------
# Display Saved Risks + Heatmap
# -----------------------
df = load_df()
st.markdown("---")
st.subheader("📋 Saved Risks")
if not df.empty:
    st.dataframe(df, use_container_width=True)
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("📥 Download CSV", data=csv, file_name="risks.csv", mime="text/csv")
else:
    st.warning("No risks logged yet. Upload logs to auto-generate risks.")

# Heatmap
if not df.empty:
    matrix = build_matrix(df)
    numeric_matrix = pd.DataFrame(matrix).apply(pd.to_numeric, errors="coerce").fillna(0)
    likelihood_labels = [1, 2, 3, 4, 5]
    impact_labels = [5, 4, 3, 2, 1]

    fig = go.Figure(
        data=go.Heatmap(
            z=numeric_matrix,
            x=likelihood_labels,
            y=impact_labels,
            colorscale=[[0.0, "#2ECC71"], [0.5, "#F4D03F"], [1.0, "#E74C3C"]],
            hovertemplate="<b>Likelihood:</b> %{x}<br><b>Impact:</b> %{y}<br><b>Risks:</b> %{z}<extra></extra>",
            showscale=True,
            zmin=0,
            zmax=float(numeric_matrix.values.max()) if numeric_matrix.values.size > 0 else 1,
            colorbar_title="Risk Level"
        )
    )
    fig.update_layout(
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        margin=dict(l=60, r=60, t=40, b=60),
        width=600, height=550
    )
    fig.add_annotation(text="📊 Organizational Risk Matrix", x=3, y=5.6, xref="x", yref="y", showarrow=False,
                       font=dict(size=16, color="#F8F9FA", family="Arial Black"))
    st.plotly_chart(fig, use_container_width=False)
