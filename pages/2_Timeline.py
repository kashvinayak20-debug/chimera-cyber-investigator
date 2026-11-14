"""Page 2 - Timeline: Reconstructed Chronology, Dynamic Transitions, and Evasion Inferences."""
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ui.common import chain_selector, events_table, page_setup, require_result, sidebar_settings, style_risk  # noqa: E402
from ui.plots import timeline_figure  # noqa: E402
from forensic.config import SOURCE_LABELS  # noqa: E402

page_setup("Attack Timeline & Evasion Detection")
sidebar_settings()
res = require_result()
if res is None:
    st.stop()

chain_id = chain_selector(res)
chain, rep = res.chain(chain_id), res.report(chain_id)
df = res.chain_events(chain_id)

# ----------------- METRIC CARDS -----------------
c = st.columns(4)
c[0].metric("Attack Confidence", f"{rep['aci']['aci']}%", rep["aci"]["tier"].upper())
c[1].metric("Chain Suspicion h(P)", f"{rep['h_score']:.4f}")
c[2].metric("Correlated Steps", rep["length"])
c[3].metric("MITRE Template Fit", f"{rep['template']['matched_count']}/{len(rep['template']['stages'])} Stages")

st.markdown(f"""
<div style="background:#111827; border:1px solid #1f2937; border-radius:8px; padding:12px 16px; margin: 14px 0px; font-size:13px; color:#d1d5db;">
    <b>Matched Pattern:</b> <span style="color:#60a5fa;">{rep['template']['template']}</span> &nbsp;|&nbsp; 
    <b>Entities:</b> {', '.join(rep['entities']) or 'Unresolved'} &nbsp;|&nbsp; 
    <b>Compromised Accounts:</b> {', '.join(rep['users']) or 'None'}
</div>
""", unsafe_allow_html=True)

# ----------------- TIMELINE STRIP -----------------
st.markdown("#### Chronological Sequence (UTC)")
fig = timeline_figure(df, rep)
st.pyplot(fig, use_container_width=True)
plt.close(fig)

# ----------------- CHRONOLOGY TABLE WITH MISSING EVENTS -----------------
st.markdown("#### Forensic Event Log & Inferred Actions")
rows = events_table(df).to_dict("records")
for m in rep.get("missing_events", []):
    rows.append({
        "step": "Inferred",
        "time (UTC)": f"between {m['expected_after']} and {m['expected_before']}",
        "event_type": f"Unlogged Stage: {m['stage']}",
        "risk": "missing",
        "source": "Inferred",
        "entity": "-",
        "user": "-",
        "rule": "Template Gap Interpolation",
        "summary": f"{m['reason']} (Confidence: {m['confidence']*100:.0f}%)"
    })
table = pd.DataFrame(rows)
table["_t"] = table["time (UTC)"].map(lambda v: v.replace("between ", "").split(" and ")[0] if isinstance(v, str) and v.startswith("between") else v)
table = table.sort_values("_t", kind="stable").drop(columns="_t").reset_index(drop=True)
st.dataframe(style_risk(table), use_container_width=True, hide_index=True)

# ----------------- TRANSITIONS ALONG THE CHAIN (EQ. 1) -----------------
st.markdown("#### Causal Transitions ($h(P) = \\prod \\alpha_i$)")
tr = []
names = df.set_index("event_id")["event_type"]
for e in chain.get("edges", []):
    tr.append({
        "Origin Stage": f"#{e['from']} {names.get(e['from'], 'UNKNOWN')}",
        "Target Stage": f"#{e['to']} {names.get(e['to'], 'UNKNOWN')}",
        "Relationship": e.get("kind", "causal"),
        "Time Delta (min)": f"{e.get('gap_min', 0):.1f}",
        "Transition Weight (α)": f"{e.get('alpha', 0.5):.2f}"
    })
st.dataframe(pd.DataFrame(tr), use_container_width=True, hide_index=True)
st.caption("Transition weights (α) quantify adversarial progression likelihood. Multi-hop chains with $h(P) \\ge 0.05$ are isolated for investigation.")

with st.expander("Supporting Raw Telemetry Logs"):
    for r in df.to_dict("records"):
        st.code(f"Step #{r['step']} | Event: {r['event_type']} | Source: {SOURCE_LABELS.get(r['source'], r['source'])} | Record ID: {r['record_id']}\n{r.get('raw', '')}", language="text")
