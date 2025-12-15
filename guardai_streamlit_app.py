# GuardAI - Streamlit frontend (UI skeleton)
# Run: pip install streamlit requests plotly
# Start: streamlit run guardai_streamlit_app.py

import streamlit as st
import requests
import json
import datetime
import random
import plotly.express as px

API_BASE = "http://127.0.0.1:8000/api"   # backend endpoints will be added later

st.set_page_config(page_title="GuardAI - Cybersecurity Assistant", layout="wide")

# --- Sidebar ---
with st.sidebar:
    st.markdown("# GuardAI")
    nav = st.radio("Navigate", ["Dashboard", "Phishing Analyzer", "Login Monitor", "Alerts", "Reports", "Settings", "Demo Data"], index=0)
    st.divider()
    st.caption("Built with Streamlit • FastAPI backend")

# --- Topbar (simple) ---
cols_top = st.columns([0.75, 0.25])
with cols_top[0]:
    st.write("")
with cols_top[1]:
    st.markdown("<div style='text-align:right'> <img src='https://via.placeholder.com/36' style='border-radius:50%'/></div>", unsafe_allow_html=True)

# Helper: mock data for demo when backend not available
def mock_url_analysis(url):
    score = random.randint(10, 95)
    verdict = "Safe" if score < 35 else ("Suspicious" if score < 65 else "Malicious")
    reasons = []

    # simple heuristics
    if "-" in url or "secure" in url.lower():
        reasons.append("Brand-like token or hyphen in domain")
    if url.count(".") > 1:
        reasons.append("Multi-level domain (possible typosquatting)")
    if score > 70:
        reasons.append("Zero-shot model: high phishing confidence")

    return {
        "url": url,
        "domain": url.split("//")[-1].split("/")[0],
        "threat_score": score,
        "verdict": verdict,
        "reasons": reasons or ["Heuristic checks"]
    }


# --- DASHBOARD ---
if nav == "Dashboard":
    st.header("Dashboard")
    col1, col2, col3 = st.columns([1.5, 1, 1])
    # System Threat Score card
    threat_score = st.session_state.get("system_threat_score", random.randint(10, 45))
    with col1:
        st.metric(label="System Threat Score", value=f"{threat_score}/100")
        st.progress(int(threat_score))
    # Quick actions
    with col2:
        if st.button("Analyze Email"):
            st.experimental_set_query_params(view="phishing")
            st.experimental_rerun()
        if st.button("Check URL"):
            st.experimental_set_query_params(view="phishing_url")
            st.experimental_rerun()
    # Alerts chart
    with col3:
        st.subheader("Alerts by Type")
        df = px.data.tips()  # placeholder
        fig = px.pie(values=[40,30,20,10], names=["Phishing","BruteForce","Anomaly","Other"], hole=0.4)
        st.plotly_chart(fig, use_container_width=True)

    st.subheader("Recent Alerts")
    alerts = st.session_state.get("alerts_demo", [
        {"id":1, "title":"Phishing attempt detected", "time":"12 minutes ago", "score":82},
        {"id":2, "title":"Multiple failed logins", "time":"1 hour ago", "score":62},
        {"id":3, "title":"Unusual login time", "time":"2 hours ago", "score":45},
    ])
    for a in alerts:
        c1, c2 = st.columns([6,1])
        with c1:
            st.write(f"**{a['title']}** — {a['time']}")
        with c2:
            st.button("View", key=f"view_{a['id']}")

# --- PHISHING ANALYZER ---
elif nav == "Phishing Analyzer":
    st.header("Phishing Analyzer")
    tabs = st.tabs(["Paste Email/Text", "Upload Email (.eml)", "Check URL Only"]) 

    # Paste Email/Text Tab
    with tabs[0]:
        raw = st.text_area("Paste full email text including headers (or just body)")
        run = st.button("Run Analysis", key="analyze_email")
        if run:
            with st.spinner("Analyzing email..."):
                resp = requests.post(
                f"{API_BASE}/analyze/email",
                json={"raw_email": raw}
                ).json()

                st.success(f"Verdict: {resp['verdict']} — Score: {resp['threat_score']}/100")
                st.markdown("**Reasons:**")
                for r in resp['reasons']:
                    st.write(f"- {r}")
                st.json(resp)

    # Upload .eml Tab
    with tabs[1]:
        eml = st.file_uploader("Upload .eml file (optional)", type=["eml"])
        if eml:
            if st.button("Analyze uploaded email"):
                st.info("Parsing and analyzing uploaded email (demo)...")
                resp = mock_url_analysis("http://secure-paytm.example/verify")
                st.json(resp)

    # Check URL Only Tab
    with tabs[2]:
        url = st.text_input("Paste URL to check")
        if st.button("Check URL"):
            with st.spinner("Checking URL..."):
                try:
                    # call backend if available
                    r = requests.post(f"{API_BASE}/analyze/url", json={"url": url})
                    data = r.json()

                except Exception as e:
                    data = {"error": str(e)}
                st.metric("Threat Score", f"{data.get('threat_score', 0)}/100", delta=None)
                st.write("**Verdict:**", data.get('verdict'))
                st.write("**Reasons:**")
                for r in data.get('reasons', []):
                    st.write(f"- {r}")
                st.json(data)

# --- LOGIN MONITOR ---
elif nav == "Login Monitor":
    st.header("Login Monitor")
    st.subheader("Simulate Login Event")
    with st.form("login_form"):
        user = st.text_input("User email", value="student@example.com")
        ip = st.text_input("IP address", value="45.33.2.11")
        device = st.text_input("Device (browser)", value="Chrome-Win")
        country = st.text_input("Country", value="Unknown")
        ts = st.datetime_input("Timestamp", value=datetime.datetime.now())
        submitted = st.form_submit_button("Submit Event")
        if submitted:
            st.success("Event ingested (demo)")
            # mock detection
            score = random.randint(10, 95)
            status = "High Risk" if score>70 else ("Suspicious" if score>40 else "Normal")
            st.write(f"Analyzed: {status} (score {score})")

    st.subheader("Recent Login Events")
    sample = [
        {"user":"a@x.com","ip":"45.33.2.11","device":"Chrome","res":"fail","ts":"2025-12-01 22:10"},
        {"user":"b@x.com","ip":"14.215.3.2","device":"Firefox","res":"success","ts":"2025-12-01 20:01"}
    ]
    st.table(sample)

# --- ALERTS ---
elif nav == "Alerts":
    st.header("Alerts")
    st.write("Filter: ")
    st.selectbox("Type", ["All","Phishing","Login","Anomaly"], index=0)
    st.write("Showing recent alerts:")
    alerts = st.session_state.get("alerts_demo", [])
    for a in alerts:
        with st.expander(f"{a['title']} — Score: {a['score']}"):
            st.write("Details about the alert")
            st.button("Mark Safe", key=f"safe_{a['id']}")
            st.button("Notify User", key=f"notify_{a['id']}")

# --- REPORTS ---
elif nav == "Reports":
    st.header("Reports")
    st.write("Generate Incident Report")
    start = st.date_input("From", value=datetime.date.today()-datetime.timedelta(days=7))
    end = st.date_input("To", value=datetime.date.today())
    if st.button("Generate PDF Report"):
        st.info("Report generation not implemented in demo")

# --- SETTINGS ---
elif nav == "Settings":
    st.header("Settings")
    threshold = st.slider("Alert threshold (score)", 0, 100, 60)
    st.write("Current threshold:", threshold)
    st.text_input("Admin email for notifications", value="admin@example.com")

# --- DEMO DATA ---
elif nav == "Demo Data":
    st.header("Demo Data & Tutorials")
    st.write("Use demo inputs to see system behavior")
    if st.button("Load Sample Phishing Email"):
        st.session_state['sample_email'] = "From: scam@phish.example\nSubject: Verify your account now\nBody: Click http://paytm-secure.co/otp"
        st.success("Sample loaded. Go to Phishing Analyzer -> Paste Email/Text and paste the sample from session_state.")

# Footer
st.markdown("---")
st.caption("GuardAI • Demo UI • Streamlit")

