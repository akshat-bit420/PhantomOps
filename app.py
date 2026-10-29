import os
import json
import pandas as pd
import streamlit as st
import plotly.express as px
from dotenv import load_dotenv

from src.generator import generate_telemetry_dataset
from src.detector import PhantomDetector
from src.reasoner import GemmaReasoner
from src.gatekeeper import Auth0Gatekeeper
from src.narrator import GhostNarrator

load_dotenv()

STATE_CACHE_FILE = "data/session_state_cache.json"
ANOMALIES_CACHE_CSV = "data/flagged_anomalies_cache.csv"

def load_persisted_state():
    if os.path.exists(STATE_CACHE_FILE):
        try:
            with open(STATE_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"autopsies": {}, "exorcised_ids": []}

def save_persisted_state(autopsies: dict, exorcised_ids: set):
    os.makedirs("data", exist_ok=True)
    with open(STATE_CACHE_FILE, "w") as f:
        json.dump({"autopsies": autopsies, "exorcised_ids": list(exorcised_ids)}, f)

st.set_page_config(
    page_title="PhantomOps | Ghost in the Machine Exorcist",
    page_icon="👻",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp { background-color: #0b0e14; color: #e6edf3; }
    .metric-card {
        background: linear-gradient(135deg, #161b22 0%, #1f242d 100%);
        border: 1px solid #30363d;
        border-left: 4px solid #8957e5;
        padding: 18px;
        border-radius: 10px;
        margin-bottom: 12px;
    }
    .critical-badge {
        background-color: #da3633; color: white; padding: 3px 10px;
        border-radius: 12px; font-size: 0.8rem; font-weight: bold;
    }
    .exorcised-banner {
        background-color: #238636; color: white; padding: 12px;
        border-radius: 8px; font-weight: bold; margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

persisted = load_persisted_state()

if "anomalies_df" not in st.session_state:
    if os.path.exists(ANOMALIES_CACHE_CSV) and os.path.exists("data/telemetry_billing.csv"):
        st.session_state.anomalies_df = pd.read_csv(ANOMALIES_CACHE_CSV)
        st.session_state.full_df = pd.read_csv("data/telemetry_billing.csv")
    else:
        st.session_state.anomalies_df = None
        st.session_state.full_df = None

if "autopsies" not in st.session_state:
    st.session_state.autopsies = persisted.get("autopsies", {})
if "exorcised_ids" not in st.session_state:
    st.session_state.exorcised_ids = set(persisted.get("exorcised_ids", []))
if "auth0_verified_state" not in st.session_state:
    st.session_state.auth0_verified_state = None

gatekeeper = Auth0Gatekeeper()
narrator = GhostNarrator()
reasoner = GemmaReasoner()

# --- Handle Auth0 Callback Redirect ---
query_params = st.query_params
if "code" in query_params and "state" in query_params:
    state_val = query_params["state"]
    code_val = query_params["code"]
    if state_val.startswith("exorcise_"):
        parts = state_val.split("_")
        if len(parts) >= 2:
            approved_resource_id = parts[1]
            token_res = gatekeeper.exchange_code_for_token(code_val)
            st.session_state.exorcised_ids.add(approved_resource_id)
            save_persisted_state(st.session_state.autopsies, st.session_state.exorcised_ids)
            st.session_state.auth0_verified_state = {
                "resource_id": approved_resource_id,
                "token_info": token_res
            }
            st.query_params.clear()

# --- Header ---
st.title("👻 PhantomOps: Local Infrastructure Ghost & Anomaly Exorcist")
st.caption(
    "**Zero-Cloud-Leakage FinOps Agent** | Powered locally by **TabPFN-3.5-Fast** (Tabular Foundation Model) "
    "+ **Google Gemma 2** (Local Root-Cause Autopsy) + **Auth0** (Human-in-the-Loop Gatekeeper) + **ElevenLabs** (Voice Briefing)"
)

if st.session_state.auth0_verified_state:
    res_id = st.session_state.auth0_verified_state["resource_id"]
    st.success(f"🔐 **Auth0 Step-Up Authorization Verified!** Human clearance granted. Ghost resource `{res_id}` has been terminated.")

# --- Sidebar Controls ---
with st.sidebar:
    st.header("⚙️ Telemetry Ingestion")
    st.write("100% of tabular detection & LLM reasoning runs **locally on your CPU**. No CSV data leaves this machine.")
    
    uploaded_file = st.file_uploader("Upload Enterprise Cloud CSV", type=["csv"])
    
    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        load_sample = st.button("⚡ Scan Telemetry", type="primary", use_container_width=True)
    with col_btn2:
        regen_data = st.button("🔄 Reset / Regen", use_container_width=True)

    if regen_data:
        with st.spinner("Generating fresh cloud telemetry & resetting exorcisms..."):
            generate_telemetry_dataset()
            st.session_state.exorcised_ids = set()
            st.session_state.autopsies = {}
            save_persisted_state({}, set())
            if os.path.exists(ANOMALIES_CACHE_CSV):
                os.remove(ANOMALIES_CACHE_CSV)
            st.session_state.anomalies_df = None
        st.success("Reset complete! Click Scan Telemetry.")

    st.divider()
    st.subheader("🛡️ Active Open-Source Stack")
    st.markdown("""
    - **Tabular Engine:** `TabPFN-3.5-Fast` (Local `.safetensors`)
    - **Reasoning LLM:** `Gemma 2 (2B)` via Local Ollama
    - **Action Security:** `Auth0` Step-Up OAuth2/HITL
    - **Audio Narrator:** `ElevenLabs` Multilingual v2
    """)

# --- Run TabPFN-3.5 Detection ---
if load_sample or uploaded_file is not None:
    csv_target = "data/telemetry_billing.csv"
    if uploaded_file is not None:
        csv_target = "data/uploaded_telemetry.csv"
        with open(csv_target, "wb") as f:
            f.write(uploaded_file.getbuffer())
    elif not os.path.exists(csv_target):
        generate_telemetry_dataset(output_path=csv_target)

    with st.spinner("🔮 Running local TabPFN-3.5-Fast forward pass across server telemetry..."):
        detector = PhantomDetector()
        st.session_state.full_df = pd.read_csv(csv_target)
        st.session_state.anomalies_df = detector.train_and_detect(csv_target)
        st.session_state.anomalies_df.to_csv(ANOMALIES_CACHE_CSV, index=False)

# --- Main Dashboard Body ---
if st.session_state.anomalies_df is not None:
    anomalies = st.session_state.anomalies_df
    full_df = st.session_state.full_df

    # Calculate savings from exorcised ghosts
    active_anomalies = anomalies[~anomalies["resource_id"].isin(st.session_state.exorcised_ids)]
    total_monthly_waste = active_anomalies["hourly_cost_usd"].sum() * 730
    saved_monthly = (anomalies["hourly_cost_usd"].sum() * 730) - total_monthly_waste

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Total Scanned Instances", f"{len(full_df)}")
    kpi2.metric("Detected Ghost Workloads", f"{len(active_anomalies)} Active", delta=f"-{len(st.session_state.exorcised_ids)} Exorcised")
    kpi3.metric("Remaining Phantom Drain", f"${total_monthly_waste:,.2f}/mo", delta=f"-${saved_monthly:,.2f}/mo Saved" if saved_monthly > 0 else None)
    kpi4.metric("TabPFN Top Confidence", f"{anomalies['ghost_confidence'].max()*100:.2f}%")

    col_chart, col_table = st.columns([1.2, 1])

    with col_chart:
        st.subheader("📡 TabPFN-3.5 Anomaly Separation Map")
        fig = px.scatter(
            anomalies,
            x="cpu_utilization_pct",
            y="memory_utilization_pct",
            size="hourly_cost_usd",
            color="anomaly_type",
            hover_name="resource_id",
            hover_data=["instance_type", "ghost_confidence", "active_connections", "uptime_hours"],
            template="plotly_dark",
            labels={
                "cpu_utilization_pct": "CPU Utilization (%)",
                "memory_utilization_pct": "Memory Utilization (%)"
            },
            height=380
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_table:
        st.subheader("📋 High-Confidence Phantom Queue")
        display_df = anomalies.copy()
        display_df["status"] = display_df["resource_id"].apply(
            lambda r: "✅ EXORCISED" if r in st.session_state.exorcised_ids else "👻 HAUNTED"
        )
        display_cols = ["resource_id", "status", "instance_type", "ghost_confidence", "hourly_cost_usd", "cpu_utilization_pct"]
        st.dataframe(display_df[display_cols], height=350, use_container_width=True)

    st.divider()

    st.subheader("🧠 Local Gemma 2 Root-Cause Autopsy & Auth0 Exorcism Console")

    selected_id = st.selectbox(
        "Select a flagged Ghost Resource to inspect and exorcise:",
        options=anomalies["resource_id"].tolist(),
        format_func=lambda x: (
            f"{'✅ [EXORCISED] ' if x in st.session_state.exorcised_ids else '👻 [HAUNTED] '}"
            f"{x} ({anomalies[anomalies['resource_id']==x]['anomaly_type'].values[0]} — "
            f"Confidence: {anomalies[anomalies['resource_id']==x]['ghost_confidence'].values[0]*100:.2f}%)"
        )
    )

    selected_row = anomalies[anomalies["resource_id"] == selected_id].iloc[0].to_dict()

    col_left, col_right = st.columns([1.3, 1])

    with col_left:
        if st.button(f"🧠 Generate Local Gemma 2 Autopsy for {selected_id}", type="primary"):
            with st.spinner(f"Querying local {os.getenv('GEMMA_MODEL', 'gemma2:2b')} via Ollama..."):
                autopsy_obj = reasoner.generate_autopsy(selected_row)
                st.session_state.autopsies[selected_id] = autopsy_obj.model_dump()
                save_persisted_state(st.session_state.autopsies, st.session_state.exorcised_ids)

        if selected_id in st.session_state.autopsies:
            rep = st.session_state.autopsies[selected_id]
            st.markdown(f"""
            <div class="metric-card">
                <span class="critical-badge">{rep['severity']}</span>
                <h4 style="margin-top:10px;">{rep['incident_title']}</h4>
                <p><strong>Root-Cause Autopsy (Gemma 2):</strong> {rep['root_cause_autopsy']}</p>
                <p><strong>Estimated Drain:</strong> <span style="color:#ff7b72;font-weight:bold;">${rep['monthly_waste_usd']:,.2f} / month</span></p>
                <p><strong>Remediation Command:</strong> <code>{rep['exorcism_command']}</code></p>
            </div>
            """, unsafe_allow_html=True)

            if st.button(f"🔊 Synthesize ElevenLabs Voice Briefing ({selected_id})"):
                with st.spinner("Generating voice briefing via ElevenLabs..."):
                    audio_file = narrator.generate_briefing_audio(rep)
                    if audio_file and os.path.exists(audio_file):
                        st.audio(audio_file, format="audio/mp3")
                    else:
                        st.warning("Could not synthesize audio. Check ELEVENLABS_API_KEY in .env.")
            else:
                cached_path = os.path.join("audio_cache", f"alert_{selected_id}.mp3")
                if os.path.exists(cached_path):
                    st.caption("🔊 Cached ElevenLabs Briefing Ready:")
                    st.audio(cached_path, format="audio/mp3")

    with col_right:
        st.markdown("### 🔐 Auth0 Human-in-the-Loop Gatekeeper")
        st.write(
            "Destructive infrastructure actions cannot be executed autonomously by the agent. "
            "Human identity verification via **Auth0** is required before terminating this instance."
        )

        if selected_id in st.session_state.exorcised_ids:
            st.markdown(
                f'<div class="exorcised-banner">✅ EXORCISED: {selected_id} has been terminated with human approval.</div>',
                unsafe_allow_html=True
            )
        else:
            cmd = st.session_state.autopsies.get(selected_id, {}).get(
                "exorcism_command", f"aws ec2 terminate-instances --instance-ids {selected_id}"
            )
            approval_req = gatekeeper.create_approval_request(selected_id, cmd)

            if approval_req["configured"]:
                st.link_button(
                    f"🛡️ Authorize & Exorcise {selected_id} via Auth0",
                    url=approval_req["auth_url"],
                    type="primary",
                    use_container_width=True
                )
            
            if st.button(f"⚡ Quick Local Sign-Off (Demo Mode) for {selected_id}", use_container_width=True):
                st.session_state.exorcised_ids.add(selected_id)
                save_persisted_state(st.session_state.autopsies, st.session_state.exorcised_ids)
                st.rerun()
else:
    st.info("👈 Click **'⚡ Scan Telemetry'** in the left sidebar to run `TabPFN-3.5-Fast` on your local telemetry dataset.")