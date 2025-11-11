# app.py — Log ingestion + IOC analysis replacement for manual risk form
import os
import re
import uuid
import importlib.util
import sys
from typing import Dict, Any

# --- robust import of helpers and ai_helper (works even with tricky package paths) ---
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
# ai_helper may not be used yet; load for future AI integration
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
import matplotlib.pyplot as plt
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
    """Query AbuseIPDB for ip reputation. Returns dict with abuseConfidenceScore or error."""
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
    """
    Map a 0-100 threat score to Likelihood and Impact on 1-5 scale.
    Thresholds are adjustable.
    """
    if score >= 80:
        likelihood = 5
        impact = 5
    elif score >= 60:
        likelihood = 4
        impact = 4
    elif score >= 40:
        likelihood = 3
        impact = 3
    elif score >= 20:
        likelihood = 2
        impact = 2
    else:
        likelihood = 1
        impact = 1
    return likelihood, impact

def create_risk_record_from_ioc(ioc_type: str, ioc_value: str, context_snippet: str, likelihood: int, impact: int) -> dict:
    """Build the standard risk record dictionary expected by save_record."""
    rid = str(uuid.uuid4())
    risk_score = score_risk(likelihood, impact)
    record = {
        "risk_id": rid,
        "risk_name": f"{ioc_type}: {ioc_value}",
        "risk_description": context_snippet[:400],  # keep it short
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": risk_score,
        "risk_cell": f"{likelihood}x{impact}",
        "owner": "AutoDetector",
        "mitigation": "",
        "timestamp": pd.Timestamp.now()
    }
    return record

# -----------------------
# Upload UI (replaces manual form)
# -----------------------
st.markdown("## 1) Upload logs to auto-detect risks")
uploaded_file = st.file_uploader("Upload log file (.txt, .log, .csv). Multiple uploads not supported in this version.", type=["txt", "log", "csv"])

ABUSEIPDB_KEY = st.secrets.get("ABUSEIPDB_API_KEY", None)

if uploaded_file:
    raw_bytes = uploaded_file.read()
    try:
        content = raw_bytes.decode("utf-8", errors="ignore")
    except Exception:
        content = str(raw_bytes)

    st.info(f"Processing {uploaded_file.name} ...")
    iocs = extract_iocs(content)

    # show counts and sample
    st.markdown("### Extracted IOCs summary")
    cols = st.columns(5)
    keys = ["IPs", "URLs", "Domains", "Hashes", "Emails"]
    for i, k in enumerate(keys):
        with cols[i]:
            st.metric(label=k, value=len(iocs.get(k, [])))
    st.markdown("---")

    # display extracted lists (collapsible)
    with st.expander("Show extracted IOCs"):
        for k in keys:
            vals = iocs.get(k, [])
            st.write(f"**{k}** ({len(vals)})")
            if vals:
                st.code("\n".join(vals))

    # reputation checks for IPs
    ip_results = []
    if iocs["IPs"]:
        st.markdown("### IP Reputation (AbuseIPDB)")
        if not ABUSEIPDB_KEY:
            st.warning("Add ABUSEIPDB_API_KEY in Streamlit secrets to enable live IP reputation checks.")
        else:
            progress = st.progress(0)
            for idx, ip in enumerate(iocs["IPs"], 1):
                res = check_abuseipdb(ip, ABUSEIPDB_KEY)
                ip_results.append(res)
                progress.progress(min(100, int((idx / len(iocs["IPs"])) * 100)))
            progress.empty()
            df_ip = pd.DataFrame(ip_results)
            st.dataframe(df_ip, use_container_width=True)
            # quick bar chart of abuse score
            try:
                st.bar_chart(df_ip.set_index("ip")["abuseConfidenceScore"])
            except Exception:
                pass
    else:
        st.info("No IPs found for reputation checks.")

    # Let user select which extracted IOCs should become risks
    st.markdown("---")
    st.markdown("## 2) Select which IOCs to convert into risks")
    to_save = []
    # prepare options grouped by type
    for t in ["IPs", "URLs", "Domains", "Hashes", "Emails"]:
        items = iocs.get(t, [])
        if items:
            chosen = st.multiselect(f"Select {t} to save as risks", options=items, key=f"choose_{t}")
            for val in chosen:
                to_save.append((t, val))

    # Option: automatic scoring without API
    auto_save = st.checkbox("Auto-save selected IOCs as risks", value=False)
    if st.button("Save selected IOCs as risks"):
        if not to_save:
            st.warning("Pick at least one IOC to save.")
        else:
            saved_count = 0
            for ioc_type, ioc_value in to_save:
                # context snippet: find surrounding text for first occurrence
                pos = content.find(ioc_value)
                start = max(0, pos - 120)
                end = min(len(content), pos + 120)
                snippet = content[start:end] if pos != -1 else f"Auto-detected {ioc_type} {ioc_value}"

                # default mapping if no abuseipdb data
                if ioc_type == "IPs":
                    # try to find ip in ip_results
                    score = None
                    for r in ip_results:
                        if r.get("ip") == ioc_value and "abuseConfidenceScore" in r:
                            score = int(r.get("abuseConfidenceScore", 0))
                            break
                    if score is None:
                        # no API data available: neutral default
                        likelihood, impact = 3, 3
                    else:
                        likelihood, impact = map_score_to_li_impact(score)
                else:
                    # for non-IP IOCs, assign medium default; may be improved later
                    likelihood, impact = 3, 3

                record = create_risk_record_from_ioc(ioc_type, ioc_value, snippet, likelihood, impact)
                save_record(record)
                saved_count += 1

            st.success(f"Saved {saved_count} IOCs as risk records.")
            # refresh page to load updated risks and heatmap
            st.experimental_rerun()

    if auto_save and to_save:
        # a simple auto-save path without pressing Save button
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
                if score is None:
                    likelihood, impact = 3, 3
                else:
                    likelihood, impact = map_score_to_li_impact(score)
            else:
                likelihood, impact = 3, 3
            record = create_risk_record_from_ioc(ioc_type, ioc_value, snippet, likelihood, impact)
            save_record(record)
            saved_count += 1
        st.success(f"Auto-saved {saved_count} IOCs as risk records.")
        st.experimental_rerun()

# -----------------------
# Existing: show saved risks and heatmap (unchanged)
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

# Heatmap (use existing build_matrix)
if not df.empty:
    matrix = build_matrix(df)
    # Ensure numeric matrix
    try:
        numeric_matrix = pd.DataFrame(matrix).apply(pd.to_numeric, errors="coerce").fillna(0)
    except Exception:
        numeric_matrix = pd.DataFrame(matrix)
    likelihood_labels = [1,2,3,4,5]
    impact_labels = [5,4,3,2,1]

    fig = go.Figure(
        data=go.Heatmap(
            z=numeric_matrix,
            x=likelihood_labels,
            y=impact_labels,
            colorscale=[[0.0, "#2ECC71"], [0.5, "#F4D03F"], [1.0, "#E74C3C"]],
            hovertemplate="<b>Likelihood:</b> %{x}<br><b>Impact:</b> %{y}<br><b>Risks:</b> %{z}<extra></extra>",
            showscale=True,
            zmin=0,
            zmax=float(numeric_matrix.values.max()) if numeric_matrix.values.size>0 else 1,
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
