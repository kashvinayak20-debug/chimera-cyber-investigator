"""Page 3 - Graph: Cross-Source Event Graph drawn with interactive PyVis and entity lanes."""
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ui.common import chain_selector, page_setup, require_result, sidebar_settings
from ui.graph_visualizer import GraphVisualizer
from forensic.config import SOURCE_LABELS

page_setup("Interactive Attack Graph")
sidebar_settings()
res = require_result()
if res is None:
    st.stop()

G = res.graph
chain_id = chain_selector(res, key="graph_chain")
chain = res.chain(chain_id)
chain_nodes = set(chain["events"])
chain_edges = {(e["from"], e["to"]) for e in chain["edges"]}

st.markdown("""
<div class="clean-card">
    <div style="font-size:15px; font-weight:600; color:#f9fafb;">Causal Attack Provenance Map</div>
    <div style="font-size:13px; color:#9ca3af; margin-top:4px; line-height:1.5;">
        Visualizing multi-hop adversary propagation across hosts, user accounts, and network interfaces.
        Red directed edges highlight the candidate attack chain reconstructed by dynamic programming.
    </div>
</div>
""", unsafe_allow_html=True)

c_mode, c_focus = st.columns([2, 1])
with c_mode:
    focus = st.checkbox("Focus view on selected attack chain only", value=True)

# Legend badges
st.markdown("""
<div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:12px 0px;">
    <span style="background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.3); color:#fca5a5; padding:3px 10px; border-radius:9999px; font-size:11px; font-weight:600;">◆ High Risk / Exfiltration</span>
    <span style="background:rgba(245,158,11,0.12); border:1px solid rgba(245,158,11,0.3); color:#fde68a; padding:3px 10px; border-radius:9999px; font-size:11px; font-weight:600;">● Suspicious Execution</span>
    <span style="background:rgba(59,130,246,0.12); border:1px solid rgba(59,130,246,0.3); color:#93c5fd; padding:3px 10px; border-radius:9999px; font-size:11px; font-weight:600;">▲ Authentication / VPN</span>
    <span style="background:rgba(107,114,128,0.12); border:1px solid rgba(107,114,128,0.3); color:#d1d5db; padding:3px 10px; border-radius:9999px; font-size:11px; font-weight:600;">● Benign Context</span>
    <span style="color:#ef4444; font-size:12px; font-weight:600; margin-left:8px;">── Red Path: Attack Chain (α ≥ 0.5)</span>
</div>
""", unsafe_allow_html=True)

# Generate and render PyVis graph
html_content = GraphVisualizer.render_pipeline_graph_html(
    res,
    chain_id=chain_id,
    height="580px",
    focus_chain=focus
)
components.html(html_content, height=600, scrolling=False)

st.markdown("#### Attack Path Transitions")
chain_rows = []
events_df = res.chain_events(chain_id).set_index("event_id")

for edge in chain.get("edges", []):
    u_data = events_df.loc[edge["from"]] if edge["from"] in events_df.index else {}
    v_data = events_df.loc[edge["to"]] if edge["to"] in events_df.index else {}
    chain_rows.append({
        "Origin": f"#{edge['from']} {u_data.get('event_type', 'EVENT')}",
        "Target": f"#{edge['to']} {v_data.get('event_type', 'EVENT')}",
        "Transition (α)": f"{edge.get('alpha', 0.5):.2f}",
        "Time Delta": f"{edge.get('gap_min', 0.0):.1f} min",
        "Connection Type": edge.get("kind", "entity")
    })

st.dataframe(pd.DataFrame(chain_rows), use_container_width=True, hide_index=True)
