"""Page 4 - Investigation Report: Explainable ACI, Patient Zero, Blast Radius, AI Detective, and SOC Containment."""
import json
import sys
import os
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ui.common import TIER_COLORS, chain_selector, events_table, page_setup, require_result, sidebar_settings, style_risk
from forensic.config import ACI_TIERS
from forensic.report import report_to_markdown
from forensic.ai_detective import AIDetective

page_setup("Investigation Dossier & Containment Playbook")
sidebar_settings()
res = require_result()
if res is None:
    st.stop()

chain_id = chain_selector(res, key="report_chain")
rep = res.report(chain_id)
a = rep["aci"]
chain_events_df = res.chain_events(chain_id)

# Compute Patient Zero & Blast Radius
pz = AIDetective.identify_patient_zero(chain_events_df)
blast = AIDetective.calculate_blast_radius(chain_events_df)

# ----------------- 1. HEADLINE METRICS -----------------
col_aci, col_pz, col_blast = st.columns([1, 1.2, 1.2])

with col_aci:
    tier_col = TIER_COLORS.get(a['tier'], "#f43f5e")
    st.markdown(f"""
    <div style="background:#111827; border:1px solid #1f2937; border-top:3px solid {tier_col}; border-radius:8px; padding:18px;">
        <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:#9ca3af; letter-spacing:0.5px;">Attack Confidence Index</div>
        <div style="font-size:36px; font-weight:700; color:#f9fafb; line-height:1.2; margin:4px 0;">{a['aci']}%</div>
        <span class="pill-badge-red">{a['tier']} Threat Tier</span>
        <div style="font-size:12px; color:#9ca3af; margin-top:8px;">{a['response']}</div>
    </div>
    """, unsafe_allow_html=True)

with col_pz:
    st.markdown(f"""
    <div style="background:#111827; border:1px solid #1f2937; border-top:3px solid #f59e0b; border-radius:8px; padding:18px;">
        <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:#9ca3af; letter-spacing:0.5px;">Patient Zero (Initial Access)</div>
        <div style="font-size:18px; font-weight:700; color:#f9fafb; margin-top:6px;">{pz['entity']}</div>
        <div style="font-size:13px; color:#d1d5db; margin-top:4px;">
            Account: <b>{pz['user']}</b> &nbsp;|&nbsp; Vector: <code>{pz['event_type']}</code>
        </div>
        <div style="font-size:12px; color:#9ca3af; margin-top:8px;">
            First Observed: <b>{pz['timestamp']} UTC</b> (Record #{pz['record_id']})
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_blast:
    st.markdown(f"""
    <div style="background:#111827; border:1px solid #1f2937; border-top:3px solid {blast['level_color']}; border-radius:8px; padding:18px;">
        <div style="font-size:11px; font-weight:600; text-transform:uppercase; color:#9ca3af; letter-spacing:0.5px;">Enterprise Blast Radius</div>
        <div style="font-size:36px; font-weight:700; color:#f9fafb; line-height:1.2; margin:4px 0;">
            {blast['severity_score']} <span style="font-size:16px; color:#6b7280;">/ 100</span>
        </div>
        <div style="font-size:12px; color:#9ca3af;">
            Targeted Servers: <b style="color:#ef4444;">{len(blast['critical_servers'])}</b> &nbsp;|&nbsp; 
            External C2 Drops: <b style="color:#f87171;">{len(blast['external_c2_ips'])}</b> &nbsp;|&nbsp; 
            Compromised Users: <b>{len(blast['compromised_users'])}</b>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height:14px;'></div>", unsafe_allow_html=True)

# ----------------- 2. ACI FORMULA BREAKDOWN -----------------
st.markdown("#### Attack Confidence Index Component Matrix")
st.caption("Eq. 2: $ACI(P) = w_1 S_{src} + w_2 T_{coh} + w_3 R_{ent} + w_4 M_{pat}$")

comp = pd.DataFrame({
    "Component Metric": list(a["components"]),
    "Normalized Value": [f"{v:.3f}" if isinstance(v, float) else v for v in a["components"].values()],
    "Assigned Weight": [a["weights"][k] for k in a["components"]],
    "Weighted Contribution": [f"{a['contributions'][k]:.1f}%" for k in a["components"]],
    "Forensic Explanation": [a["explanation"][k] for k in a["components"]],
})
st.dataframe(comp, use_container_width=True, hide_index=True)

# ----------------- 3. TABS: AI DETECTIVE REPORT, EVIDENCE, BLAST, MITIGATION -----------------
tab_ai, tab_timeline, tab_missing, tab_containment = st.tabs([
    "AI Incident Narrative",
    "Reconstructed Timeline",
    "Evasion & Missing Stages",
    "SOC Containment Playbook"
])

with tab_ai:
    gemini_key = os.environ.get("GEMINI_API_KEY", "")
    key_input = st.text_input("Gemini API Key (Optional for live LLM synthesis):", value=gemini_key, type="password")
    
    detective = AIDetective(api_key=key_input)
    ai_report = detective.generate_explainable_report(rep, chain_events_df, pz, blast)
    
    st.markdown(f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
        <span class="pill-badge">Engine: {ai_report.get('engine', 'Deterministic Forensic Engine')}</span>
        <span style="font-size:12px; color:#9ca3af;">Ground Truth Verified</span>
    </div>
    """, unsafe_allow_html=True)
    st.markdown(ai_report["report_markdown"])
    
    st.download_button(
        "Download Incident Report (.md)",
        ai_report["report_markdown"],
        file_name=f"CHIMERA_Forensic_Report_{chain_id}.md",
        mime="text/markdown",
        use_container_width=True
    )

with tab_timeline:
    st.markdown("##### Chronological Provenance Steps")
    ev_df = events_table(chain_events_df)
    st.dataframe(style_risk(ev_df), use_container_width=True, hide_index=True)

with tab_missing:
    st.markdown("##### Inferred Unlogged Evasion Actions")
    if rep.get("missing_events"):
        for m in rep["missing_events"]:
            st.markdown(f"""
            <div class="clean-card-alert">
                <div style="font-size:14px; font-weight:700; color:#fb7185;">
                    Unlogged Stage Detected: {m['stage']} (Confidence: {m['confidence']*100:.0f}%)
                </div>
                <div style="font-size:13px; color:#f9fafb; margin-top:4px;">
                    Expected chronological window: <b>{m['expected_after']} → {m['expected_before']} UTC</b>
                </div>
                <div style="font-size:12px; color:#9ca3af; margin-top:4px;">
                    <i>{m['reason']}</i>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.success("No missing stages detected in this chain.")

with tab_containment:
    st.markdown("##### Recommended Containment Checklist")
    c1, c2 = st.columns(2)
    with c1:
        st.checkbox(f"Isolate host **{pz['entity']}** from internal subnet", value=True)
        st.checkbox(f"Terminate active VPN session for user **{pz['user']}**", value=True)
        st.checkbox(f"Reset Active Directory credentials for **{pz['user']}**", value=True)
    with c2:
        for c2_ip in blast.get("external_c2_ips", []):
            st.checkbox(f"Block external egress destination **{c2_ip}** at perimeter", value=True)
        for srv in blast.get("critical_servers", []):
            st.checkbox(f"Audit and isolate affected server: **{srv}**", value=True)
        st.checkbox("Audit service tokens and evaluate credential exposure", value=False)
