import os
import json
import urllib.parse
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from dotenv import load_dotenv

from src.generator import generate_telemetry_dataset
from src.live_scanner import scan_live_windows_processes, kill_real_windows_process
from src.detector import PhantomDetector
from src.reasoner import GemmaReasoner
from src.gatekeeper import Auth0Gatekeeper
from src.narrator import GhostNarrator

load_dotenv()

STATE_CACHE_FILE = "data/session_state_cache.json"
ANOMALIES_CACHE_CSV = "data/flagged_anomalies_cache.csv"
FULL_CACHE_CSV = "data/full_telemetry_cache.csv"

def load_persisted_state():
    if os.path.exists(STATE_CACHE_FILE):
        try:
            with open(STATE_CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"autopsies": {}, "exorcised_ids": [], "scan_mode": "cloud", "audit_receipts": {}}

def save_persisted_state(autopsies: dict, exorcised_ids: set, scan_mode: str = "cloud", audit_receipts: dict = None):
    os.makedirs("data", exist_ok=True)
    with open(STATE_CACHE_FILE, "w") as f:
        json.dump({
            "autopsies": autopsies,
            "exorcised_ids": list(exorcised_ids),
            "scan_mode": scan_mode,
            "audit_receipts": audit_receipts or {}
        }, f)

st.set_page_config(
    page_title="PhantomOps | Ghost in the Machine Exorcist",
    page_icon="👻",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;600;800&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    code, pre, .mono-text {
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stApp {
        background-color: #07090e;
        color: #d1d7e0;
    }

    [data-testid="stMetric"] {
        background: radial-gradient(circle at top left, #121824 0%, #0c1017 100%);
        border: 1px solid #1f293d;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    [data-testid="stMetricLabel"] {
        font-family: 'JetBrains Mono', monospace;
        text-transform: uppercase;
        font-size: 0.75rem !important;
        letter-spacing: 0.08em;
        color: #8b949e !important;
    }
    [data-testid="stMetricValue"] {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        color: #f0f6fc !important;
    }

    .metric-card {
        background: #0d1117;
        border: 1px solid #30363d;
        border-left: 4px solid #f85149;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 16px;
    }

    .receipt-card {
        background: #090d16;
        border: 1px solid #238636;
        border-left: 4px solid #3fb950;
        padding: 16px;
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        margin-top: 12px;
    }

    .critical-badge {
        background: rgba(248, 81, 73, 0.15);
        color: #f85149;
        border: 1px solid rgba(248, 81, 73, 0.4);
        padding: 2px 8px;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.75rem;
        font-weight: 600;
    }

    .exorcised-banner {
        background-color: rgba(35, 134, 54, 0.2);
        border: 1px solid #2ea043;
        color: #3fb950;
        padding: 12px;
        border-radius: 8px;
        font-family: 'JetBrains Mono', monospace;
        font-weight: bold;
        margin-top: 10px;
    }

    section[data-testid="stSidebar"] {
        background-color: #090d14;
        border-right: 1px solid #161f30;
    }

    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: transparent;
    }
    .stTabs [data-baseweb="tab"] {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        border-radius: 6px 6px 0 0;
        padding: 8px 16px;
        color: #8b949e;
        background: #0d1117;
        border: 1px solid #21262d;
        border-bottom: none;
    }
    .stTabs [aria-selected="true"] {
        background: #161b22 !important;
        color: #58a6ff !important;
        border-color: #388bfd !important;
    }

    button[kind="primary"] {
        background: #238636 !important;
        border: 1px solid #2ea043 !important;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

persisted = load_persisted_state()

if "anomalies_df" not in st.session_state:
    if os.path.exists(ANOMALIES_CACHE_CSV) and os.path.exists(FULL_CACHE_CSV):
        st.session_state.anomalies_df = pd.read_csv(ANOMALIES_CACHE_CSV)
        st.session_state.full_df = pd.read_csv(FULL_CACHE_CSV)
    else:
        st.session_state.anomalies_df = None
        st.session_state.full_df = None

if "autopsies" not in st.session_state:
    st.session_state.autopsies = persisted.get("autopsies", {})
if "exorcised_ids" not in st.session_state:
    st.session_state.exorcised_ids = set(persisted.get("exorcised_ids", []))
if "scan_mode" not in st.session_state:
    st.session_state.scan_mode = persisted.get("scan_mode", "cloud")
if "audit_receipts" not in st.session_state:
    st.session_state.audit_receipts = persisted.get("audit_receipts", {})
if "auth0_verified_state" not in st.session_state:
    st.session_state.auth0_verified_state = None
if "seance_Log" not in st.session_state:
    st.session_state.seance_Log = {}
if "play_exorcism_sfx" not in st.session_state:
    st.session_state.play_exorcism_sfx = False

gatekeeper = Auth0Gatekeeper()
narrator = GhostNarrator()
reasoner = GemmaReasoner()

@st.cache_resource
def get_detector():
    return PhantomDetector()

detector = get_detector()

# --- Auth0 Callback Handling ---
query_params = st.query_params
if "code" in query_params and "state" in query_params:
    state_val = urllib.parse.unquote_plus(query_params["state"])
    code_val = query_params["code"]
    if state_val.startswith("exorcise_"):
        parts = state_val.split("_")
        if len(parts) >= 2:
            approved_resource_id = "_".join(parts[1:-1]) if len(parts) > 2 else parts[1]
            token_res = gatekeeper.exchange_code_for_token(code_val)
            os_kill_res = kill_real_windows_process(approved_resource_id)

            cmd_used = st.session_state.autopsies.get(approved_resource_id, {}).get(
                "exorcism_command", f"taskkill /F /T /PID {approved_resource_id}"
            )
            receipt = gatekeeper.build_audit_receipt(approved_resource_id, cmd_used, token_res)
            st.session_state.audit_receipts[approved_resource_id] = receipt
            st.session_state.exorcised_ids.add(approved_resource_id)
            st.session_state.play_exorcism_sfx = True

            save_persisted_state(
                st.session_state.autopsies,
                st.session_state.exorcised_ids,
                st.session_state.scan_mode,
                st.session_state.audit_receipts
            )
            st.session_state.auth0_verified_state = {
                "resource_id": approved_resource_id,
                "token_info": token_res,
                "os_kill_message": os_kill_res.get("message", ""),
                "receipt": receipt
            }
            st.query_params.clear()

st.title("👻 PhantomOps: Local Infrastructure Ghost & Anomaly Exorcist")
st.caption(
    "**Zero-Cloud-Leakage FinOps Agent** | **TabPFN-3.5-Fast** (Classifier + Regressor) "
    "+ **Google Gemma 2** (Autopsy + Séance) + **Auth0** (Step-Up JWT) + **ElevenLabs** (STT + TTS)"
)

if st.session_state.auth0_verified_state:
    res_id = st.session_state.auth0_verified_state["resource_id"]
    kill_msg = st.session_state.auth0_verified_state.get("os_kill_message", "")
    st.success(f"🔐 **Auth0 Step-Up Verified:** Ghost `{res_id}` exorcised. {kill_msg}")

if st.session_state.play_exorcism_sfx:
    sfx_file = narrator.generate_exorcism_sfx()
    if sfx_file and os.path.exists(sfx_file):
        st.audio(sfx_file, format="audio/mp3", autoplay=True)
    st.session_state.play_exorcism_sfx = False

with st.sidebar:
    st.header("⚙️ Telemetry Ingestion Mode")
    mode_choice = st.radio(
        "Select Target Environment:",
        ["🖥️ Live Windows PC Kernel (psutil)", "☁️ Enterprise Cloud CSV"],
        index=0 if st.session_state.scan_mode == "live" else 1
    )

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        run_scan = st.button("⚡ Scan Now", type="primary", width='stretch')
    with col_btn2:
        reset_btn = st.button("🔄 Reset State", width='stretch')

    uploaded_file = None
    if "Cloud CSV" in mode_choice:
        uploaded_file = st.file_uploader("Or Upload Custom Cloud CSV", type=["csv"])

    if reset_btn:
        st.session_state.exorcised_ids = set()
        st.session_state.autopsies = {}
        st.session_state.audit_receipts = {}
        save_persisted_state({}, set(), st.session_state.scan_mode, {})
        for f in [ANOMALIES_CACHE_CSV, FULL_CACHE_CSV]:
            if os.path.exists(f):
                os.remove(f)
        st.session_state.anomalies_df = None
        st.rerun()

    st.divider()
    st.subheader("🏆 Sponsor Integrations")
    st.markdown("""
    - **Prior Labs:** `TabPFNClassifier` + `TabPFNRegressor`
    - **Google DeepMind:** Local `Gemma 2` Autopsy + Séance Roleplay
    - **Auth0:** Step-Up OAuth2 + SHA-256 Execution Receipt
    - **ElevenLabs:** `scribe_v1` STT + Multi-Voice TTS + SFX
    """)

if run_scan or uploaded_file is not None:
    if "Live Windows" in mode_choice:
        st.session_state.scan_mode = "live"
        with st.spinner("Snapshotting active Windows kernel processes via psutil..."):
            csv_target = "data/live_os_telemetry.csv"
            scan_live_windows_processes(csv_target)
            st.session_state.full_df = pd.read_csv(csv_target)
            st.session_state.anomalies_df = detector.train_and_detect(csv_target)
    else:
        st.session_state.scan_mode = "cloud"
        csv_target = "data/telemetry_billing.csv"
        if uploaded_file is not None:
            csv_target = "data/uploaded_telemetry.csv"
            with open(csv_target, "wb") as f:
                f.write(uploaded_file.getbuffer())
        elif not os.path.exists(csv_target):
            generate_telemetry_dataset(output_path=csv_target)
        with st.spinner("Running TabPFN-3.5 on cloud telemetry..."):
            st.session_state.full_df = pd.read_csv(csv_target)
            st.session_state.anomalies_df = detector.train_and_detect(csv_target)

    st.session_state.anomalies_df.to_csv(ANOMALIES_CACHE_CSV, index=False)
    st.session_state.full_df.to_csv(FULL_CACHE_CSV, index=False)
    save_persisted_state(
        st.session_state.autopsies,
        st.session_state.exorcised_ids,
        st.session_state.scan_mode,
        st.session_state.audit_receipts
    )

if st.session_state.anomalies_df is not None and len(st.session_state.anomalies_df) > 0:
    anomalies = st.session_state.anomalies_df
    full_df = st.session_state.full_df

    active_anomalies = anomalies[~anomalies["resource_id"].isin(st.session_state.exorcised_ids)]
    total_monthly_waste = active_anomalies["hourly_cost_usd"].sum() * 730
    saved_monthly = (anomalies["hourly_cost_usd"].sum() * 730) - total_monthly_waste

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric(
        "Scanned Entities",
        f"{len(full_df)} {'Live PIDs' if st.session_state.scan_mode == 'live' else 'Nodes'}"
    )
    kpi2.metric("Detected Ghosts", f"{len(active_anomalies)} Active", delta=f"-{len(st.session_state.exorcised_ids)} Exorcised")
    kpi3.metric("Monthly Drain Estimate", f"${total_monthly_waste:,.2f}/mo", delta=f"-${saved_monthly:,.2f}/mo Saved" if saved_monthly > 0 else None)
    kpi4.metric("TabPFN Max Confidence", f"{anomalies['ghost_confidence'].max()*100:.2f}%")

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
            hover_data=["instance_type", "ghost_confidence", "active_connections", "region"],
            template="plotly_dark",
            height=360
        )
        st.plotly_chart(fig, width='stretch')

    with col_table:
        st.subheader("📋 High-Confidence Phantom Queue")
        display_df = anomalies.copy()
        display_df["status"] = display_df["resource_id"].apply(
            lambda r: "✅ EXORCISED" if r in st.session_state.exorcised_ids else "👻 HAUNTED"
        )
        cols = ["resource_id", "status", "ghost_confidence", "memory_utilization_pct", "cpu_utilization_pct", "active_connections"]
        st.dataframe(display_df[cols], height=330, width='stretch')

    st.divider()

    selected_id = st.selectbox(
        "🎯 Select a Flagged Ghost Process to Investigate:",
        options=anomalies["resource_id"].tolist(),
        format_func=lambda x: (
            f"{'✅ [EXORCISED] ' if x in st.session_state.exorcised_ids else '👻 [HAUNTED] '}"
            f"{x} — {anomalies[anomalies['resource_id']==x]['anomaly_type'].values[0]} "
            f"(Confidence: {anomalies[anomalies['resource_id']==x]['ghost_confidence'].values[0]*100:.2f}%)"
        )
    )
    selected_row = anomalies[anomalies["resource_id"] == selected_id].iloc[0].to_dict()

    tab1, tab2, tab3 = st.tabs([
        "🧠 1. Gemma 2 Autopsy & Auth0 Exorcism",
        "🎙️ 2. Two-Way Voice Séance",
        "📈 3. TabPFN Forecaster & Counterfactuals"
    ])

    with tab1:
        col_left, col_right = st.columns([1.25, 1])
        with col_left:
            if st.button(f"🧠 Generate Local Gemma 2 Autopsy for {selected_id}", type="primary"):
                with st.spinner("Generating local Gemma 2 root-cause autopsy via Ollama..."):
                    autopsy_obj = reasoner.generate_autopsy(selected_row)
                    st.session_state.autopsies[selected_id] = autopsy_obj.model_dump()
                    save_persisted_state(
                        st.session_state.autopsies,
                        st.session_state.exorcised_ids,
                        st.session_state.scan_mode,
                        st.session_state.audit_receipts
                    )

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

                if st.button(f"🔊 Synthesize Incident Briefing ({selected_id})"):
                    audio_file = narrator.generate_briefing_audio(rep)
                    if audio_file and os.path.exists(audio_file):
                        fmt = "audio/wav" if audio_file.endswith(".wav") else "audio/mp3"
                        st.audio(audio_file, format=fmt)

        with col_right:
            st.markdown("### 🔐 Auth0 Human-in-the-Loop Gatekeeper")
            st.write("Verifies step-up authorization and produces an immutable SHA-256 audit entry.")

            cmd = st.session_state.autopsies.get(selected_id, {}).get(
                "exorcism_command", f"taskkill /F /T /PID {selected_id}"
            )

            if selected_id in st.session_state.exorcised_ids:
                st.markdown(f'<div class="exorcised-banner">✅ EXORCISED: {selected_id} terminated.</div>', unsafe_allow_html=True)
                receipt = st.session_state.audit_receipts.get(selected_id)
                if receipt:
                    st.markdown(f"""
                    <div class="receipt-card">
                        <div style="color:#3fb950;font-weight:bold;margin-bottom:6px;">📜 AUTH0 EXECUTION RECEIPT</div>
                        <div><strong>Receipt ID:</strong> {receipt['receipt_id']}</div>
                        <div><strong>Operator (sub):</strong> {receipt['operator_subject']}</div>
                        <div><strong>Command:</strong> <code>{receipt['authorized_command']}</code></div>
                        <div style="word-break:break-all;"><strong>SHA-256:</strong> <span style="color:#a371f7;">{receipt['sha256_action_binding']}</span></div>
                    </div>
                    """, unsafe_allow_html=True)
                    st.download_button(
                        label="⬇️ Download Audit Ledger (JSON)",
                        data=json.dumps(receipt, indent=2),
                        file_name=f"signed_exorcism_{receipt['receipt_id']}.json",
                        mime="application/json",
                        width='stretch'
                    )
            else:
                approval_req = gatekeeper.create_approval_request(selected_id, cmd)
                if approval_req["configured"]:
                    st.link_button(
                        f"🛡️ Authorize & Exorcise {selected_id} via Auth0",
                        url=approval_req["auth_url"],
                        type="primary",
                        width='stretch'
                    )

                if st.button(f"💀 Execute Immediate Local Exorcism ({selected_id})", width='stretch'):
                    kill_res = kill_real_windows_process(selected_id)
                    receipt = gatekeeper.build_audit_receipt(selected_id, cmd, {"sub": "local-operator"})
                    st.session_state.audit_receipts[selected_id] = receipt
                    st.session_state.exorcised_ids.add(selected_id)
                    st.session_state.play_exorcism_sfx = True
                    save_persisted_state(
                        st.session_state.autopsies,
                        st.session_state.exorcised_ids,
                        st.session_state.scan_mode,
                        st.session_state.audit_receipts
                    )
                    st.toast(kill_res["message"])
                    st.rerun()

    with tab2:
        st.markdown("### 🎙️ Live Voice Séance: Interrogate Process")
        st.caption("1️⃣ Click record on microphone → 2️⃣ Click stop (⏹️) and wait 1 sec → 3️⃣ Click Conduct Séance.")
        voice_recording = st.audio_input("Record an interrogation question:")
        text_fallback = st.text_input("Or type your question directly:", value="Why is spawn_zombie.py consuming high system resources?")

        if st.button("🕯️ Conduct Séance with Ghost Process", type="primary"):
            with st.spinner("Processing speech & querying local Gemma 2..."):
                if voice_recording is not None and len(voice_recording.getvalue()) > 100:
                    user_q = narrator.transcribe_seance_question(voice_recording.getvalue())
                else:
                    user_q = text_fallback

                ghost_reply = reasoner.conduct_seance_reply(selected_row, user_q)
                audio_reply_path = narrator.synthesize_seance_reply(selected_id, ghost_reply)
                st.session_state.seance_Log[selected_id] = {
                    "question": user_q,
                    "reply": ghost_reply,
                    "audio": audio_reply_path
                }

        if selected_id in st.session_state.seance_Log:
            log = st.session_state.seance_Log[selected_id]
            st.info(f"**🧑 You asked:** \"{log['question']}\"")
            st.warning(f"**👻 {selected_id} replies:** \"{log['reply']}\"")
            if log["audio"] and os.path.exists(log["audio"]):
                fmt = "audio/wav" if log["audio"].endswith(".wav") else "audio/mp3"
                st.audio(log["audio"], format=fmt, autoplay=True)

    with tab3:
        st.markdown("### 📈 `TabPFNRegressor` 30-Day Doomsday Trajectory")
        forecast = detector.forecast_doomsday_trajectory(full_df, selected_row)

        fcol1, fcol2 = st.columns([1, 2.2])
        with fcol1:
            st.metric("⏳ Estimated Time to OOM", f"{forecast['hours_to_oom_crash']} Hours", delta="Memory Saturation", delta_color="inverse")
            st.metric("💸 30-Day Projected Waste", f"${forecast['projected_30d_loss']:,.2f}")
        with fcol2:
            fig_f = go.Figure()
            fig_f.add_trace(go.Scatter(
                x=forecast["days"], y=forecast["unfixed_cumulative_usd"],
                mode="lines+markers", name="Unchecked Burn ($)",
                line=dict(color="#ff7b72", width=3)
            ))
            fig_f.add_trace(go.Scatter(
                x=forecast["days"], y=forecast["exorcised_cumulative_usd"],
                mode="lines", name="Post-Exorcism ($0)",
                line=dict(color="#3fb950", width=3, dash="dash")
            ))
            fig_f.update_layout(
                title=f"Cost Escalation Model ({selected_id})",
                xaxis_title="Days",
                yaxis_title="USD",
                template="plotly_dark",
                height=280
            )
            st.plotly_chart(fig_f, width='stretch')

        st.divider()
        st.markdown("#### 🧬 TabPFN Counterfactual Simulator")
        cf_col1, cf_col2 = st.columns([1, 1.4])

        with cf_col1:
            sim_mem = st.slider("Simulate Memory (%)", 0.1, 100.0, float(selected_row.get("memory_utilization_pct", 10.0)), 0.5)
            sim_conn = st.slider("Simulate Active Threads", 1, 250, int(selected_row.get("active_connections", 25)), 1)
            sim_res = detector.explain_and_simulate(full_df, selected_row, sim_mem, sim_conn)
            st.metric("Counterfactual Confidence", f"{sim_res['counterfactual_confidence_pct']}%")

        with cf_col2:
            attr_df = pd.DataFrame({
                "Feature": list(sim_res["attributions"].keys()),
                "Blame Impact (%)": list(sim_res["attributions"].values())
            }).sort_values(by="Blame Impact (%)", ascending=True)

            fig_attr = px.bar(
                attr_df, x="Blame Impact (%)", y="Feature", orientation="h",
                title=f"Zero-Shot Feature Attribution ({selected_id})",
                template="plotly_dark", color="Blame Impact (%)", color_continuous_scale="Purples"
            )
            fig_attr.update_layout(height=260, showlegend=False)
            st.plotly_chart(fig_attr, width='stretch')
else:
    st.info("👈 Select **'🖥️ Live Windows PC Kernel (psutil)'** and click **'⚡ Scan Now'**.")