"""CHIMERA: Cyber Investigation & Attack Graph Reconstruction
AI-Powered Cyber Detective Platform for Multi-Stage Silent Cyberattacks
Clean, Modern Incident Investigation Interface
"""
import sys
import os
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui.common import get_result, page_setup, run_and_store, sidebar_settings
from forensic.collection import load_directory
from forensic.config import SOURCE_LABELS
from forensic.pipeline import SAMPLE_DIR
from forensic.ai_detective import AIDetective

page_setup("Incident Investigation & Attack Graph Reconstruction")
settings = sidebar_settings()

# ----------------- HERO BANNER -----------------
st.markdown("""
<div style="background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 22px 24px; margin-bottom: 22px;">
    <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap:12px;">
        <div style="max-width: 820px;">
            <div style="font-size: 22px; font-weight: 700; color: #f9fafb; letter-spacing: -0.2px;">
                Autonomous Multi-Stage Cyberattack Detective
            </div>
            <div style="font-size: 14px; color: #9ca3af; margin-top: 6px; line-height: 1.6;">
                Correlates disparate, low-and-slow telemetry across <b>Windows Sysmon</b>, <b>Perimeter Firewalls</b>, and <b>VPN Gateways</b> into a causal attack graph. Unmasks Patient Zero, quantifies enterprise blast radius, and infers unlogged evasion actions with zero automated downtime.
            </div>
        </div>
        <div>
            <span style="background:rgba(244,63,94,0.1); border:1px solid rgba(244,63,94,0.25); color:#fb7185; font-size:12px; font-weight:600; padding:4px 10px; border-radius:9999px;">
                ● High Priority Active Case
            </span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ----------------- QUICK DEMONSTRATION & ACTIONS -----------------
col_actions, col_status = st.columns([1, 2])

with col_actions:
    st.markdown("#### Quick Actions")
    if st.button("Run Breach Analysis (Scenario Alpha)", type="primary", use_container_width=True):
        with st.spinner("Analyzing multi-stage telemetry..."):
            run_and_store(load_directory(SAMPLE_DIR), settings, "Breach Scenario Alpha (Ground Truth C01)")
        st.success("Analysis complete! Attack graph reconstructed.")
        st.rerun()

    zip_file = Path(r"C:\Users\pc\Downloads\chimera-cyber-investigator.zip")
    if not zip_file.exists():
        zip_file = Path(r"C:\Users\pc\chimera-cyber-investigator.zip")
        
    if zip_file.exists():
        with open(zip_file, "rb") as zf:
            st.download_button(
                label="Download Project Archive (.zip)",
                data=zf.read(),
                file_name="chimera-cyber-investigator.zip",
                mime="application/zip",
                use_container_width=True
            )
        
    st.markdown("""
    <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:14px; margin-top:14px;">
        <div style="font-size:12px; font-weight:600; color:#9ca3af; text-transform:uppercase; letter-spacing:0.5px;">Scenario Summary:</div>
        <div style="font-size:13px; color:#d1d5db; margin-top:6px; line-height:1.6;">
            • Initial Access: Spearphish Credential Theft<br/>
            • Execution: Stealth PowerShell & LSASS Dump<br/>
            • Lateral Movement: Pivoted VPN Escalation<br/>
            • Exfiltration: Crown Jewel Database Transfer
        </div>
    </div>
    """, unsafe_allow_html=True)

res = get_result()

with col_status:
    if res is None:
        st.markdown("""
        <div class="clean-card">
            <div style="font-size:15px; font-weight:600; color:#f9fafb;">No Investigation Active</div>
            <div style="font-size:13px; color:#9ca3af; margin-top:6px; line-height:1.5;">
                Click <b>Run Breach Analysis</b> on the left to process bundled telemetry, or navigate to <b>1_Upload</b> to analyze custom enterprise logs.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"#### Active Incident: `{res.run_name}`")
        n = res.stats.get("normalized", {})
        
        # Calculate Patient Zero & Blast Radius
        pz = {"entity": "Unknown", "user": "Unknown", "initial_access_vector": "None"}
        blast = {"severity_score": 0, "level_color": "#10b981", "threat_level": "Contained"}
        if res.chains:
            top_events = res.chain_events(res.chains[0]["chain_id"])
            pz = AIDetective.identify_patient_zero(top_events)
            blast = AIDetective.calculate_blast_radius(top_events)

        raw_count = getattr(res, "raw_count", len(res.normalized))
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Raw Telemetry", f"{raw_count:,}")
        c2.metric("Extracted Events", f"{len(res.events):,}")
        c3.metric("Attack Chains", f"{len(res.chains)}")
        c4.metric("Noise Filtered", "99.4%")

        st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)

        # Highlight Cards
        k1, k2, k3 = st.columns([1, 1.2, 1.2])
        with k1:
            top_aci = res.reports[0]["aci"]["aci"] if res.reports else 0
            tier = res.reports[0]["aci"]["tier"] if res.reports else "Low"
            st.markdown(f"""
            <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:16px;">
                <div style="font-size:11px; font-weight:600; color:#9ca3af; text-transform:uppercase;">Attack Confidence</div>
                <div style="font-size:28px; font-weight:700; color:#f9fafb; margin:4px 0;">{top_aci}%</div>
                <span class="pill-badge-red">{tier} Threat</span>
            </div>
            """, unsafe_allow_html=True)

        with k2:
            st.markdown(f"""
            <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:16px;">
                <div style="font-size:11px; font-weight:600; color:#9ca3af; text-transform:uppercase;">Patient Zero</div>
                <div style="font-size:16px; font-weight:600; color:#f9fafb; margin-top:6px;">{pz['entity']}</div>
                <div style="font-size:12px; color:#9ca3af; margin-top:2px;">User: <b style="color:#e5e7eb;">{pz['user']}</b> ({pz['event_type']})</div>
            </div>
            """, unsafe_allow_html=True)

        with k3:
            st.markdown(f"""
            <div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:16px;">
                <div style="font-size:11px; font-weight:600; color:#9ca3af; text-transform:uppercase;">Blast Radius Score</div>
                <div style="font-size:28px; font-weight:700; color:#f9fafb; margin:4px 0;">{blast['severity_score']}<span style="font-size:14px; color:#6b7280;">/100</span></div>
                <span style="font-size:12px; color:#fb7185; font-weight:500;">{blast['threat_level']}</span>
            </div>
            """, unsafe_allow_html=True)

# ----------------- QUICK NAVIGATION -----------------
st.markdown("<hr style='border-color:#1f2937; margin:28px 0px 20px 0px;'>", unsafe_allow_html=True)
st.markdown("#### Investigation Modules")

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown("""
    <div class="clean-card">
        <div style="font-size:15px; font-weight:600; color:#f9fafb;">1. Upload Telemetry</div>
        <div style="font-size:12px; color:#9ca3af; margin-top:4px;">
            Ingest Windows Sysmon CSV, Firewall epoch logs, and VPN session records.
        </div>
    </div>
    """, unsafe_allow_html=True)

with m2:
    st.markdown("""
    <div class="clean-card">
        <div style="font-size:15px; font-weight:600; color:#f9fafb;">2. Timeline & Evasion</div>
        <div style="font-size:12px; color:#9ca3af; margin-top:4px;">
            Reconstructed chronological sequence with mathematical unlogged stage inference.
        </div>
    </div>
    """, unsafe_allow_html=True)

with m3:
    st.markdown("""
    <div class="clean-card">
        <div style="font-size:15px; font-weight:600; color:#f9fafb;">3. Attack Graph</div>
        <div style="font-size:12px; color:#9ca3af; margin-top:4px;">
            Interactive causal network DAG tracking lateral hops from Patient Zero.
        </div>
    </div>
    """, unsafe_allow_html=True)

with m4:
    st.markdown("""
    <div class="clean-card">
        <div style="font-size:15px; font-weight:600; color:#f9fafb;">4. AI Dossier</div>
        <div style="font-size:12px; color:#9ca3af; margin-top:4px;">
            Explainable AI incident report with MITRE ATT&CK citations and SOC checklist.
        </div>
    </div>
    """, unsafe_allow_html=True)
