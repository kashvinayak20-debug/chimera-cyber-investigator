"""Page 1 - Upload: Telemetry Ingestion & Multi-Stage Forensic Pre-processing."""
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ui.common import get_result, page_setup, run_and_store, sidebar_settings, style_risk  # noqa: E402
from forensic.collection import detect_source, load_bytes, load_directory                   # noqa: E402
from forensic.config import SOURCES, SOURCE_LABELS                                          # noqa: E402
from forensic.pipeline import SAMPLE_DIR                                                    # noqa: E402
from forensic.sample_data import generate                                                   # noqa: E402

page_setup("Telemetry Ingestion & Pre-processing")
settings = sidebar_settings()

st.markdown("""
<div class="clean-card">
    <div style="font-size:15px; font-weight:600; color:#f9fafb;">Heterogeneous Log Ingestion</div>
    <div style="font-size:13px; color:#9ca3af; margin-top:4px; line-height:1.5;">
        Ingest multi-vendor enterprise logs to be normalized into a canonical 22-column forensic schema with unified UTC timestamps.
        Select the bundled scenario or upload custom enterprise log files.
    </div>
</div>
""", unsafe_allow_html=True)

mode = st.radio("Data Source:", ["Bundled Breach Scenario (Ground Truth C01)", "Upload Custom Log Files"], horizontal=True)
raw_logs = []

if mode.startswith("Bundled"):
    c1, c2 = st.columns([3, 1])
    with c2:
        st.markdown("##### Scenario Seed")
        seed = st.number_input("RNG Seed", 0, 9999, 7, 1)
        if st.button("Regenerate Telemetry", use_container_width=True):
            info = generate(int(seed), SAMPLE_DIR)
            st.success(f"Generated {info['windows']} Windows, {info['firewall']} Firewall, {info['vpn']} VPN records.")
            
    raw_logs = load_directory(SAMPLE_DIR)
    with c1:
        st.markdown("##### Detected Telemetry Feeds (`data/samples/`):")
        for lg in raw_logs:
            st.markdown(f"- **`{lg.name}`** → {SOURCE_LABELS[lg.source]} ({lg.line_count:,} lines)")
else:
    st.markdown("""
    <div style="background:#111827; border:1px dashed #374151; border-radius:8px; padding:14px; margin-bottom:14px;">
        <span style="font-size:12px; color:#9ca3af;">
            <b>Supported formats:</b> Windows / Sysmon <code>CSV</code>; 
            Firewall <code>&lt;epoch&gt; action=... src=... dst=... dpt=... bytes_out=...</code>; 
            VPN <code>&lt;ISO-8601&gt; action=connect user=... session=... client_ip=... assigned_ip=...</code>
        </span>
    </div>
    """, unsafe_allow_html=True)
    files = st.file_uploader("Upload Log Files", type=["csv", "log", "txt"], accept_multiple_files=True)
    for f in files or []:
        data = f.getvalue()
        text = data.decode("utf-8", errors="replace")
        guess = detect_source(f.name, text)
        cols = st.columns([2, 2])
        cols[0].markdown(f"📄 `{f.name}`")
        src = cols[1].selectbox(f"Format for {f.name}", SOURCES, index=SOURCES.index(guess) if guess else 0,
                                format_func=lambda s: SOURCE_LABELS[s], key=f"src_{f.name}")
        raw_logs.append(load_bytes(f.name, data, src))

col_name, col_btn = st.columns([3, 1])
with col_name:
    run_name = st.text_input("Investigation Run Identifier:", "Breach Scenario Alpha" if mode.startswith("Bundled") else "Custom Ingestion")
with col_btn:
    st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
    run_clicked = st.button("Run Pipeline", type="primary", disabled=not raw_logs, use_container_width=True)

if run_clicked:
    with st.spinner("Executing pipeline: Ingestion → Normalization → Extraction → Entity Resolution → Graph Search..."):
        res = run_and_store(raw_logs, settings, run_name)
    st.success(f"Pipeline executed successfully: {len(res.events)} events extracted, {len(res.entities)} entities resolved, {len(res.chains)} attack chains identified.")

res = get_result()
if res is None:
    st.stop()

st.divider()
st.subheader(f"Pipeline Execution Summary: `{res.run_name}`")
st_ = res.stats
m = st.columns(6)
m[0].metric("1. Raw Sources", len(st_.get("collected", {})))
m[1].metric("2. Records (UTC)", st_.get("normalized", {}).get("total", len(res.normalized)))
m[2].metric("3. Extracted Events", len(res.events))
m[3].metric("4. Entity Clusters", f"{len(res.entities)}")
m[4].metric("5. Graph DAG", f"{res.graph.number_of_nodes()} N / {res.graph.number_of_edges()} E")
m[5].metric("6. Attack Paths", len(res.chains))

with st.expander("Stage 2: Normalized Canonical Records (22-Column Schema)", expanded=False):
    df = res.normalized.copy()
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(df.drop(columns=["raw"], errors="ignore"), use_container_width=True, height=280)
    dropped = st_.get("normalized", {}).get("dropped_no_timestamp", 0)
    if dropped:
        st.caption(f"{dropped} record(s) dropped due to unparseable timestamps.")

with st.expander("Stage 3: Extracted Forensic Events (Categorized by Rule Catalog)", expanded=True):
    ev = res.events.copy()
    ev["timestamp"] = ev["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        style_risk(ev[["event_id", "timestamp", "source", "event_type", "stage", "risk", "rule", "entity_label", "user", "summary"]]),
        use_container_width=True,
        height=280
    )
    st.caption("Event Distribution: " + ", ".join(f"**{k}**: {v}" for k, v in st_.get("events", {}).get("by_type", {}).items()))

with st.expander("Stage 4: Entity Resolution & Identifier Links (Union-Find)", expanded=False):
    c_ent1, c_ent2 = st.columns(2)
    with c_ent1:
        st.markdown("##### Unified Identity Entities")
        st.dataframe(res.entities, use_container_width=True)
    with c_ent2:
        st.markdown("##### Cross-Log Identifier Links")
        st.dataframe(res.links, use_container_width=True, height=260)
