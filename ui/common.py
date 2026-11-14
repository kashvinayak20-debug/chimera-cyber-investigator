"""Shared helpers for Streamlit pages: Modern Clean Theme, settings sidebar, result state, formatting."""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from forensic.collection import RawLog                       # noqa: E402
from forensic.config import SOURCE_LABELS, Settings           # noqa: E402
from forensic.pipeline import PipelineResult, run_pipeline    # noqa: E402
from forensic.storage import DEFAULT_DB, load_run, save_run   # noqa: E402

from ui.plots import RISK_COLORS                             # noqa: E402

TIER_COLORS = {
    "Low": "#10b981",       # Emerald
    "Medium": "#f59e0b",    # Amber
    "High": "#f97316",      # Orange
    "Critical": "#f43f5e"   # Rose
}

MODERN_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* Global Font & Canvas */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

/* Background */
.stApp {
    background-color: #0b0f19 !important;
}

/* Header Navbar */
.app-navbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 10px 18px;
    margin-bottom: 22px;
}

.app-title-wrap {
    display: flex;
    align-items: center;
    gap: 12px;
}

.status-dot {
    width: 8px;
    height: 8px;
    background-color: #10b981;
    border-radius: 50%;
    display: inline-block;
}

.pill-badge {
    background: rgba(59, 130, 246, 0.12);
    border: 1px solid rgba(59, 130, 246, 0.25);
    color: #60a5fa;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 9999px;
}

.pill-badge-red {
    background: rgba(244, 63, 94, 0.12);
    border: 1px solid rgba(244, 63, 94, 0.25);
    color: #fb7185;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 9999px;
}

/* Clean Card Components */
.clean-card {
    background: #111827;
    border: 1px solid #1f2937;
    border-radius: 8px;
    padding: 18px 20px;
    margin: 10px 0px;
}

.clean-card-alert {
    background: rgba(244, 63, 94, 0.05);
    border: 1px solid rgba(244, 63, 94, 0.25);
    border-radius: 8px;
    padding: 18px 20px;
    margin: 10px 0px;
}

.clean-card-warning {
    background: rgba(245, 158, 11, 0.05);
    border: 1px solid rgba(245, 158, 11, 0.25);
    border-radius: 8px;
    padding: 18px 20px;
    margin: 10px 0px;
}

/* Metric Cards Override */
[data-testid="stMetric"] {
    background: #111827 !important;
    border: 1px solid #1f2937 !important;
    border-radius: 8px !important;
    padding: 14px 18px !important;
}

[data-testid="stMetricLabel"] {
    color: #9ca3af !important;
    font-size: 12px !important;
    font-weight: 500 !important;
}

[data-testid="stMetricValue"] {
    color: #f9fafb !important;
    font-size: 26px !important;
    font-weight: 700 !important;
}

/* Buttons */
.stButton>button {
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    border-radius: 6px !important;
    padding: 8px 16px !important;
    transition: all 0.2s ease !important;
}

.stButton>button[kind="primary"] {
    background: #2563eb !important;
    border: 1px solid #3b82f6 !important;
    color: #ffffff !important;
    box-shadow: none !important;
}

.stButton>button[kind="primary"]:hover {
    background: #1d4ed8 !important;
    border-color: #60a5fa !important;
}

.stButton>button[kind="secondary"] {
    background: #1f2937 !important;
    border: 1px solid #374151 !important;
    color: #f3f4f6 !important;
}

.stButton>button[kind="secondary"]:hover {
    border-color: #60a5fa !important;
    color: #ffffff !important;
}

/* Tabs Styling */
.stTabs [data-baseweb="tab-list"] {
    gap: 6px !important;
    border-bottom: 1px solid #1f2937 !important;
    padding-bottom: 2px !important;
}

.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    color: #9ca3af !important;
    padding: 8px 16px !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    border-radius: 6px !important;
}

.stTabs [aria-selected="true"] {
    background: #1f2937 !important;
    color: #f9fafb !important;
    font-weight: 600 !important;
}

/* Tables & Dataframes */
[data-testid="stDataFrame"] {
    border: 1px solid #1f2937 !important;
    border-radius: 8px !important;
}

/* Code Blocks */
pre, code {
    font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace !important;
    background: #111827 !important;
    border: 1px solid #1f2937 !important;
    border-radius: 4px !important;
}
</style>
"""


def page_setup(title: str):
    """Sets wide layout, injects modern stylesheet, and renders clean top navbar."""
    st.set_page_config(
        page_title=f"CHIMERA | {title}",
        layout="wide",
        page_icon="🛡️",
        initial_sidebar_state="expanded"
    )
    # Inject Clean CSS
    st.markdown(MODERN_CSS, unsafe_allow_html=True)
    
    # Modern Minimalist Navbar
    st.markdown(f"""
    <div class="app-navbar">
        <div class="app-title-wrap">
            <span class="status-dot"></span>
            <span style="font-size:14px; font-weight:700; color:#f9fafb; letter-spacing:0.3px;">CHIMERA</span>
            <span style="font-size:13px; color:#6b7280;">•</span>
            <span style="font-size:13px; color:#d1d5db; font-weight:500;">Investigation Copilot</span>
            <span class="pill-badge">v2.5 Engine</span>
        </div>
        <div style="font-size:12px; color:#9ca3af; display:flex; align-items:center; gap:8px;">
            <span>Telemetry: <b style="color:#10b981;">Connected</b></span>
            <span style="color:#4b5563;">|</span>
            <span>Clock: <b>UTC</b></span>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.title(title)


def get_settings() -> Settings:
    if "settings" not in st.session_state:
        st.session_state["settings"] = Settings()
    return st.session_state["settings"]


def sidebar_settings() -> Settings:
    """Clean sliders for pipeline knobs. Changing them marks the result as stale."""
    s = get_settings()
    with st.sidebar:
        st.markdown("""
        <div style="padding:6px 0px 14px 0px; border-bottom:1px solid #1f2937; margin-bottom:14px;">
            <div style="font-size:15px; font-weight:700; color:#f9fafb;">Pipeline Parameters</div>
            <div style="font-size:12px; color:#9ca3af;">Deterministic Thresholds & Weights</div>
        </div>
        """, unsafe_allow_html=True)

        with st.expander("⚖️ ACI Equation Weights (w1–w4)", expanded=False):
            st.caption("Eq. 2: $ACI(P) = w_1 S_{src} + w_2 T_{coh} + w_3 R_{ent} + w_4 M_{pat}$")
            w_src = st.slider("w1 Source Diversity (S_src)", 0.0, 1.0, float(s.w_src), 0.05)
            w_coh = st.slider("w2 Temporal Coherence (T_coh)", 0.0, 1.0, float(s.w_coh), 0.05)
            w_ent = st.slider("w3 Entity Resolution (R_ent)", 0.0, 1.0, float(s.w_ent), 0.05)
            w_pat = st.slider("w4 Pattern Alignment (M_pat)", 0.0, 1.0, float(s.w_pat), 0.05)
            
        with st.expander("🕸️ Provenance DAG & Chain Search", expanded=False):
            same_w = st.slider("Same-entity window (min)", 5, 240, int(s.same_entity_window_min), 5)
            temp_w = st.slider("Temporal proximity window (min)", 1, 60, int(s.temporal_window_min), 1)
            thr = st.slider("Chain threshold h(P)", 0.01, 0.5, float(s.chain_threshold), 0.01)
            min_t = st.slider("Min transition weight (α)", 0.1, 0.9, float(s.min_transition), 0.05)
            min_len = st.slider("Min chain length", 2, 6, int(s.min_chain_length), 1)
            
        with st.expander("🔍 Extraction & Infiltration Knobs", expanded=False):
            upload_mb = st.slider("EXTERNAL_UPLOAD threshold (MB)", 1, 500, int(s.upload_min_bytes / 1024 / 1024), 1)
            tz = st.number_input("Windows log clock UTC offset (hours)", -12.0, 14.0, float(s.windows_tz_offset_hours), 0.5)

        new = Settings(
            windows_tz_offset_hours=tz,
            upload_min_bytes=upload_mb * 1024 * 1024,
            same_entity_window_min=same_w,
            temporal_window_min=temp_w,
            chain_threshold=thr,
            min_transition=min_t,
            min_chain_length=min_len,
            w_src=w_src,
            w_coh=w_coh,
            w_ent=w_ent,
            w_pat=w_pat,
            user_bridge_window_min=s.user_bridge_window_min,
            max_chain_length=s.max_chain_length,
            max_chains=s.max_chains,
            coherence_ideal_gap_min=s.coherence_ideal_gap_min,
            coherence_max_gap_min=s.coherence_max_gap_min
        )
        st.session_state["settings"] = new
        res = st.session_state.get("result")
        if res is not None and res.settings.to_dict() != new.to_dict():
            st.warning("⚠️ Parameters modified.")
            if st.button("Re-run Pipeline with Parameters", use_container_width=True, type="primary"):
                raw = st.session_state.get("raw_logs")
                if raw:
                    run_and_store(raw, new, res.run_name)
                    st.rerun()
                else:
                    st.info("Raw logs are not in memory; re-run from the Upload page.")
    return new


def run_and_store(raw_logs: list[RawLog], settings: Settings, name: str) -> PipelineResult:
    result = run_pipeline(raw_logs, settings, run_name=name)
    try:
        result.run_id = save_run(result, name, DEFAULT_DB)
    except Exception as exc:
        st.warning(f"Result computed but could not be saved to SQLite: {exc}")
    st.session_state["result"] = result
    st.session_state["raw_logs"] = raw_logs
    return result


def get_result() -> PipelineResult | None:
    """Current result from session, else the latest run persisted in SQLite."""
    res = st.session_state.get("result")
    if res is None:
        try:
            res = load_run(None, DEFAULT_DB)
        except Exception:
            res = None
        if res is not None:
            st.session_state["result"] = res
    return res


def require_result() -> PipelineResult | None:
    res = get_result()
    if res is None or not res.chains:
        st.info("No investigation data loaded yet. Go to **1_Upload** or run the demonstration below.")
        if res is not None:
            st.caption(f"Last run '{res.run_name}' produced {len(res.events)} events but no candidate attack paths.")
        return None
    return res


def chain_selector(res: PipelineResult, key: str = "chain_select") -> str:
    options = [
        f"{r['chain_id']}  —  ACI {r['aci']['aci']}% [{r['aci']['tier'].upper()}], {r['length']} events, "
        f"Entity: {', '.join(r['entities']) or 'Unresolved'}"
        for r in res.reports
    ]
    choice = st.selectbox("Select Candidate Attack Chain (Ranked by ACI):", options, key=key)
    return choice.split()[0]


def events_table(df: pd.DataFrame, cols: list[str] | None = None) -> pd.DataFrame:
    cols = cols or ["step", "timestamp", "event_type", "risk", "source", "entity_label", "user", "rule", "summary"]
    cols = [c for c in cols if c in df.columns]
    out = df[cols].copy()
    if "timestamp" in out:
        out["timestamp"] = out["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    if "source" in out:
        out["source"] = out["source"].map(SOURCE_LABELS).fillna(out["source"])
    return out.rename(columns={"timestamp": "time (UTC)", "entity_label": "entity"})


def style_risk(df: pd.DataFrame):
    if "risk" not in df.columns:
        return df
    
    def _color_row(val):
        v = str(val).lower()
        if v == "high":
            return "background-color: rgba(239, 68, 68, 0.15); color: #f87171; font-weight: 600;"
        elif v == "suspicious":
            return "background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; font-weight: 600;"
        elif v == "missing":
            return "background-color: rgba(139, 92, 246, 0.15); color: #c084fc; font-weight: 600;"
        elif v == "benign":
            return "background-color: rgba(59, 130, 246, 0.08); color: #93c5fd;"
        return ""

    return df.style.map(_color_row, subset=["risk"])
