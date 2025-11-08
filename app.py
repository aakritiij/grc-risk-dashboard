import importlib.util
import os
import sys

# --- Load Helpers ---
HELPERS_PATH = os.path.join(os.path.dirname(__file__), "src", "grc_risk_dashboard", "helpers.py")
spec = importlib.util.spec_from_file_location("helpers", HELPERS_PATH)
helpers = importlib.util.module_from_spec(spec)
sys.modules["helpers"] = helpers
spec.loader.exec_module(helpers)

# --- Load AI Helper ---
AI_HELPER_PATH = os.path.join(os.path.dirname(__file__), "src", "ai_helper.py")
spec_ai = importlib.util.spec_from_file_location("ai_helper", AI_HELPER_PATH)
ai_helper = importlib.util.module_from_spec(spec_ai)
spec_ai.loader.exec_module(ai_helper)

# Import helper functions
load_df = helpers.load_df
save_record = helpers.save_record
score_risk = helpers.score_risk
auto_assign = helpers.auto_assign
build_matrix = helpers.build_matrix

# --- Streamlit and other imports ---
import streamlit as st
import pandas as pd
import numpy as np
import uuid
import seaborn as sns
import matplotlib.pyplot as plt

# ----------------------------
# 🧩 Basic Authentication System
# ----------------------------

# Hardcoded credentials (demo)
VALID_USERNAME = "admin"
VALID_PASSWORD = "secure120"

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# --- LOGIN PAGE ---
if not st.session_state.authenticated:
    st.set_page_config(page_title="GRC Risk Dashboard", layout="wide")

    # Custom CSS for layout
    st.markdown(
        """
        <style>
        .block-container {
            max-width: 700px;
            padding-top: 4rem;
            margin: auto;
        }
        .demo-box {
            background-color: rgba(35, 55, 95, 0.8);
            border-left: 4px solid #1E90FF;
            padding: 1rem 1.3rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            color: #DDE6F2;
        }
        .stTextInput > div > div > input {
            border-radius: 10px;
        }
        .stButton > button {
            width: 100%;
            border-radius: 10px;
            font-weight: 600;
            background-color: #1E90FF;
            color: white;
        }
        .stButton > button:hover {
            background-color: #187bcd;
            color: white;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    # Title
    st.markdown("<h1 style='text-align:center;'>🔐 GRC Dashboard Login</h1>", unsafe_allow_html=True)

    # Demo credentials info card
    st.markdown(
        """
        <div class='demo-box'>
            <b>👤 Demo Credentials</b><br>
            Username: <b>admin</b><br>
            Password: <b>secure120</b>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Login form (no extra containers)
    with st.form("login_form"):
        st.markdown("<div class='login-box'>", unsafe_allow_html=True)

        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", placeholder="Enter your password", type="password")

        submitted = st.form_submit_button("Login")

        st.markdown("</div>", unsafe_allow_html=True)

        if submitted:
            if username == VALID_USERNAME and password == VALID_PASSWORD:
                st.session_state.authenticated = True
                st.success("✅ Login successful! Loading dashboard...")
                st.rerun()
            else:
                st.error("❌ Invalid username or password.")

    st.stop()

# ------------------------------------------------------
# DASHBOARD PAGE
# ------------------------------------------------------
st.set_page_config(page_title="GRC Risk Dashboard", layout="wide")
st.title("🛡️ GRC Risk Dashboard")

# Logout button
if st.sidebar.button("🚪 Logout"):
    st.session_state.authenticated = False
    st.rerun()

st.sidebar.info("Use this dashboard to log and analyze organizational risks.")

# ------------------------------------------------------
# Risk Entry Form
# ------------------------------------------------------
with st.form("risk_form"):
    st.subheader("Log a New Risk")

    risk_name = st.text_input("Risk Name")
    risk_description = st.text_area("Risk Description")
    owner = st.text_input("Risk Owner")

    auto_assign_flag = st.checkbox("Auto-assign Likelihood & Impact")

    if not auto_assign_flag:
        likelihood = st.slider("Likelihood (1 = Very Low, 5 = Very High)", 1, 5, 3)
        impact = st.slider("Impact (1 = Very Low, 5 = Very High)", 1, 5, 3)
    else:
        likelihood, impact = None, None

    submitted = st.form_submit_button("Submit Risk")

    if submitted:
        # Validate input
        if not risk_name or not risk_description or not owner:
            st.error("Please fill in all fields before submitting.")
            st.stop()

        # Generate unique ID
        risk_id = str(uuid.uuid4())

        # Auto-assign likelihood and impact if enabled
        if auto_assign_flag:
            auto_values = auto_assign(risk_description)
            if auto_values:
                likelihood, impact = auto_values
                st.info(f"Auto-assigned values → Likelihood: {likelihood}, Impact: {impact}")
            else:
                st.warning("No keyword matched for auto-assignment. Please select values manually.")
                st.stop()

        # Final validation
        if likelihood is None or impact is None:
            st.error("Likelihood and Impact values are required.")
            st.stop()

        # Calculate score and prepare record
        risk_score = score_risk(likelihood, impact)
        risk_cell = f"{likelihood}x{impact}"
        record = {
            "risk_id": risk_id,
            "risk_name": risk_name,
            "risk_description": risk_description,
            "likelihood": likelihood,
            "impact": impact,
            "risk_score": risk_score,
            "risk_cell": risk_cell,
            "owner": owner,
            "timestamp": pd.Timestamp.now()
        }

        # Save record
        save_record(record)
        st.success("✅ Risk saved successfully!")

        # Refresh page
        st.rerun()

# ------------------------------------------------------
# Display Saved Risks
# ------------------------------------------------------
df = load_df()

st.subheader("📋 Saved Risks")
if not df.empty:
    st.dataframe(df, use_container_width=True)

    # --- Download button ---
    csv = df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Download Risk Data as CSV",
        data=csv,
        file_name="risks.csv",
        mime="text/csv",
        use_container_width=True
    )
else:
    st.warning("No risks logged yet. Please add a new risk above.")

# ------------------------------------------------------
# Generate and Display Heatmap
# ------------------------------------------------------
if not df.empty:
    matrix = build_matrix(df)

    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(
        matrix,
        annot=True,
        fmt="d",
        cmap="YlOrRd",
        cbar=True,
        xticklabels=np.arange(1, 6),
        yticklabels=list(reversed(np.arange(1, 6))),
        ax=ax
    )
    ax.set_xlabel("Likelihood")
    ax.set_ylabel("Impact")
    ax.set_title("Risk Heatmap (Likelihood × Impact)")

    st.subheader("🔥 Risk Heatmap")
    st.pyplot(fig)

# ------------------------------------------------------
# AI Risk Mitigation Panel
# ------------------------------------------------------
st.sidebar.markdown("### 🤖 AI Risk Mitigation Assistant")

user_risk_desc = st.sidebar.text_area(
    "Describe a risk scenario",
    placeholder="e.g., The organization suffered a data breach due to exposed credentials."
)

if st.sidebar.button("Generate Mitigation Suggestions"):
    if user_risk_desc.strip():
        suggestions = ai_helper.get_mitigation_suggestions(user_risk_desc)
        st.sidebar.success("AI-Generated Mitigation Recommendations:")
        for i, s in enumerate(suggestions, 1):
            st.sidebar.write(f"{i}. {s}")
    else:
        st.sidebar.warning("Please enter a risk description first.")
