# 🛡️ CHIMERA: Cyber Investigation & Attack Graph Reconstruction
> **AI-Powered Cyber Detective Platform for Multi-Stage Silent Cyberattacks**  
> *Built with an Explainable Seven-Stage Digital Forensic Timeline Engine*

---

## 🌟 The Problem
Modern cyber adversaries don't smash windows; they walk in with stolen credentials, move quietly across disparate systems over days or weeks, and keep each action below volumetric alert thresholds.
- **Traditional SIEM Flaw:** Disparate events (a 2 AM login, a service token upgrade, an internal database query, a large egress transfer) look harmless in isolation. No single event crosses an alert threshold.
- **Messy & Out-of-Order Telemetry:** Enterprise logs arrive out-of-order with clock skew and are 99%+ normal background noise.
- **CHIMERA's Goal:** Like a seasoned detective putting red strings on a corkboard, CHIMERA reads heterogeneous raw logs (**Windows / Sysmon**, **Firewall / Network**, **VPN / Auth**), resolves entities, reconstructs the causal attack graph DAG, infers missing unlogged evasion steps, calculates the **Attack Confidence Index (ACI)**, isolates **Patient Zero**, quantifies the **Blast Radius**, and generates an **Explainable AI Forensic Report** citing exact log lines.

---

## 🏛️ The Seven-Stage Forensic Pipeline

```
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ 1. COLLECTION   │ ───► │ 2. NORMALIZATION│ ───► │ 3. EXTRACTION   │
│ Detect source   │      │ Canonical 22 col│      │ Rule catalog    │
│ Keep raw intact │      │ UTC timestamp   │      │ Risk levels     │
└─────────────────┘      └─────────────────┘      └─────────────────┘
                                                           │
┌─────────────────┐      ┌─────────────────┐               ▼
│ 6. TIMELINE     │ ◄─── │ 5. EVENT GRAPH  │ ◄─── ┌─────────────────┐
│ DP max-h chain  │      │ NetworkX DAG    │      │ 4. ENTITY RES.  │
│ Missing events  │      │ Transitions α   │      │ Union-Find      │
└─────────────────┘      └─────────────────┘      │ Link confidence │
         │                                        └─────────────────┘
         ▼
┌───────────────────────────────────────────────────────────────────┐
│ 7. EXPLAINABLE AI & REPORT                                        │
│ - Attack Confidence Index (ACI Eq. 2)                             │
│ - Patient Zero Initial Access Vector                              │
│ - Enterprise Blast Radius (0-100 severity)                        │
│ - Gemini 2.5 Flash / Deterministic XAI Incident Narrative         │
│ - Actionable SOC Containment Checklist                            │
└───────────────────────────────────────────────────────────────────┘
```

---

## 📐 Mathematical Foundations

### 1. Chain Suspicion Index (Eq. 1)
For a candidate attack path $P = (e_1, e_2, \dots, e_n)$ over the directed acyclic graph (DAG):
$$h(P) = \prod_{i=1}^{n-1} \alpha(e_i, e_{i+1})$$
where $\alpha \in [0.5, 1.0]$ represents the empirical transition probability between forensic event stages (e.g., `POWERSHELL_EXEC` $\rightarrow$ `CREDENTIAL_DUMP` $= 0.95$).

### 2. Attack Confidence Index (ACI, Eq. 2)
$$ACI(P) = w_1 S_{src} + w_2 T_{coh} + w_3 R_{ent} + w_4 M_{pat}$$
* **$S_{src}$ (Source Diversity):** Ratio of distinct log sources providing non-benign evidence.
* **$T_{coh}$ (Temporal Coherence):** Mean inter-event time gap score (1.0 for gaps $\le 15$ min, decaying linearly to 0.0 at 120 min).
* **$R_{ent}$ (Entity Resolution Confidence):** Mean confidence score of the resolved identity cluster.
* **$M_{pat}$ (Pattern Alignment):** Product of MITRE template stage coverage and strict chronological ordering score.

### 3. Missing Event Inference
When an attacker evades logging or deletes audit records, CHIMERA mathematically infers missing stages:
$$\text{Confidence} = 0.5 \cdot \text{Coverage} + 0.25 \cdot [P_{prev}] + 0.25 \cdot [P_{next}]$$

### 4. Blast Radius Severity Scoring (0–100)
$$\text{Score} = \min(100, 25 \cdot N_{\text{Critical Servers}} + 20 \cdot N_{\text{C2 Drops}} + 15 \cdot N_{\text{Accounts}} + 10 \cdot N_{\text{Workstations}})$$

---

## 🚀 Quickstart Guide

### 1. Requirements & Setup
```bash
# Clone or extract archive
cd chimera-cyber-investigator

# Install verified dependencies
pip install -r requirements.txt
```

### 2. Command-Line Execution
```bash
# Run end-to-end pipeline on sample attack telemetry
python -m forensic.pipeline

# Score against ground-truth benchmarks
python -m forensic.evaluate
```
*Expected Evaluation Results:*
```json
{
  "chain_id": "C01",
  "timeline_completeness": 1.0,
  "correlation_precision": 1.0,
  "reconstruction_accuracy": 1.0,
  "missing_stage_detected": true,
  "aci": 87.6,
  "tier": "Critical"
}
```

### 3. Launch the Interactive SOC Dashboard
```bash
streamlit run app.py
```
Open **`https://chimera-cyber-investigator.onrender.com/
`** in your browser.

---

## 🖥️ Multi-Page Dashboard Architecture

1. **`app.py` (SOC Command Center):**  
   High-level incident KPIs, pipeline status, Patient Zero summary, and one-click demo launcher.
2. **`pages/1_Upload.py` (Ingestion & Normalizer):**  
   Supports multi-source raw logs (Sysmon CSV, Firewall, VPN) or custom enterprise logs with automated source detection and sample dataset regeneration.
3. **`pages/2_Timeline.py` (Attack Chronology):**  
   Interactive timeline strip, chronological sequence table, transition weights $\alpha$, and missing event warnings.
4. **`pages/3_Graph.py` (Attack Graph Corkboard):**  
   Dual-engine visualization:
   - **Interactive PyVis Corkboard:** Physics-driven, color-coded node graph (Red = High Risk, Orange = Execution, Purple = Auth/VPN, Yellow = Crown Jewels).
   - **Entity Lanes Timeline:** Matplotlib multi-lane chronological diagram.
5. **`pages/4_Investigation_Report.py` (AI Detective & Blast Radius):**  
   - Patient Zero entry vector and initial log citation.
   - Attack Confidence Index formula breakdown table.
   - Gemini 2.5 Flash / Offline Deterministic incident report.
   - Blast Radius impact assessment & SOC containment checklist.
   - One-click export to Markdown (`.md`) and JSON.

---


=======
# chimera-cyber-investigator
AI-powered Cyber Detective Platform that reconstructs stealthy multi stage cyber attacks from heterogeneous logs (Windows, Firewall, VPNs) into an explainable casual attack graph. Features unlogged evasion detection, Patient Zero isolation and Blast Radius scoring.

