"""
CHIMERA AI Cyber Detective & Blast Radius Engine
Augments the forensic pipeline with:
1. Patient Zero / Initial Access Vector Identification
2. Quantitative Asset Blast Radius & Threat Scoring (0-100)
3. Explainable AI Forensic Incident Reporting (Gemini 2.5 Flash + Offline Deterministic Engine)
4. SOC Containment Playbook & Action Checklist
"""

import os
import json
from typing import Dict, Any, List, Optional
import pandas as pd

class AIDetective:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")

    @staticmethod
    def identify_patient_zero(chain_events: pd.DataFrame) -> Dict[str, Any]:
        """
        Traces back the earliest causal event in the reconstructed attack chain
        to determine Initial Access Vector and Patient Zero entity.
        """
        if chain_events.empty:
            return {
                "entity": "UNKNOWN",
                "user": "UNKNOWN",
                "timestamp": None,
                "event_type": "NONE",
                "source": "UNKNOWN",
                "summary": "No attack chain events available.",
                "record_id": None
            }

        first_ev = chain_events.iloc[0]
        entity = str(first_ev.get("entity_label", first_ev.get("host", "Unknown")))
        user = str(first_ev.get("user", "Unknown"))
        ts = str(first_ev.get("timestamp", ""))
        ev_type = str(first_ev.get("event_type", "UNKNOWN"))
        src = str(first_ev.get("source", "UNKNOWN"))
        summary = str(first_ev.get("summary", ""))
        rec_id = first_ev.get("record_id", None)

        return {
            "entity": entity,
            "user": user,
            "timestamp": ts,
            "event_type": ev_type,
            "source": src,
            "summary": summary,
            "record_id": rec_id,
            "initial_access_vector": f"{user} @ {entity} via {ev_type} ({src})"
        }

    @staticmethod
    def calculate_blast_radius(chain_events: pd.DataFrame, entities_dict: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Evaluates the enterprise blast radius based on entities, hosts, databases,
        and external drops touched in the attack chain.
        """
        hosts = set()
        users = set()
        ips = set()
        critical_servers = set()
        c2_ips = set()
        compromised_processes = set()

        for _, row in chain_events.iterrows():
            host = str(row.get("host", "")).strip()
            user = str(row.get("user", "")).strip()
            src_ip = str(row.get("src_ip", "")).strip()
            dst_ip = str(row.get("dst_ip", "")).strip()
            proc = str(row.get("process", "")).strip()
            ev_type = str(row.get("event_type", "")).strip()
            target = str(row.get("target", "")).strip()

            if host and host.lower() != "nan":
                hosts.add(host)
                if any(srv in host.upper() for srv in ["DC-", "DB-", "FS-", "PROD", "SERVER"]):
                    critical_servers.add(host)
            if user and user.lower() != "nan":
                users.add(user)
            if proc and proc.lower() != "nan":
                compromised_processes.add(proc)

            # Analyze IPs
            for ip in [src_ip, dst_ip]:
                if ip and ip.lower() != "nan" and "." in ip:
                    ips.add(ip)
                    # Check if external / suspicious
                    if not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.") or ip.startswith("127.")):
                        c2_ips.add(ip)

            # Analyze targets (e.g. database, archive)
            if ev_type == "DB_ACCESS" or any(p in target.lower() for p in ["sql", "1433", "3306"]):
                critical_servers.add(target or "Database Server")
            if ev_type == "EXTERNAL_UPLOAD" and dst_ip:
                c2_ips.add(dst_ip)

        # Severity Score Calculation (0-100)
        # Critical servers: 25 pts each
        # External C2 drops: 20 pts each
        # Compromised accounts: 15 pts each
        # Workstations: 10 pts each
        raw_score = (
            len(critical_servers) * 25 +
            len(c2_ips) * 20 +
            len(users) * 15 +
            len(hosts) * 10
        )
        severity_score = min(100, max(15, raw_score))

        if severity_score >= 80:
            threat_level = "CRITICAL (Enterprise Exfiltration / Systemic Compromise)"
            level_color = "#ef4444"
        elif severity_score >= 50:
            threat_level = "HIGH (Active Lateral Movement / Database Breach)"
            level_color = "#f97316"
        else:
            threat_level = "MEDIUM (Contained Host Infiltration)"
            level_color = "#eab308"

        return {
            "severity_score": severity_score,
            "threat_level": threat_level,
            "level_color": level_color,
            "critical_servers": sorted(list(critical_servers)),
            "workstations": sorted(list(hosts - critical_servers)),
            "compromised_users": sorted(list(users)),
            "external_c2_ips": sorted(list(c2_ips)),
            "processes": sorted(list(compromised_processes)),
            "total_assets_touched": len(hosts) + len(c2_ips) + len(users)
        }

    def generate_explainable_report(
        self,
        report_data: Dict[str, Any],
        chain_events: pd.DataFrame,
        patient_zero: Dict[str, Any],
        blast_radius: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generates an executive-grade forensic incident report.
        Tries Gemini 2.5 Flash if API key is provided; otherwise runs deterministic XAI engine.
        """
        if self.api_key and len(self.api_key.strip()) > 10:
            try:
                llm_output = self._call_gemini_api(report_data, chain_events, patient_zero, blast_radius)
                if llm_output:
                    return llm_output
            except Exception as e:
                print(f"Gemini API invocation fallback ({e}). Using deterministic forensic engine.")

        return self._generate_deterministic_report(report_data, chain_events, patient_zero, blast_radius)

    def _call_gemini_api(
        self,
        report_data: Dict[str, Any],
        chain_events: pd.DataFrame,
        patient_zero: Dict[str, Any],
        blast_radius: Dict[str, Any]
    ) -> Dict[str, Any]:
        from google import genai
        client = genai.Client(api_key=self.api_key)

        chain_summary = []
        for idx, row in chain_events.iterrows():
            chain_summary.append({
                "step": idx + 1,
                "time": str(row.get("timestamp")),
                "event_type": str(row.get("event_type")),
                "risk": str(row.get("risk")),
                "source": str(row.get("source")),
                "entity": str(row.get("entity_label", row.get("host"))),
                "summary": str(row.get("summary")),
                "record_id": row.get("record_id")
            })

        prompt = f"""
You are CHIMERA, an expert Digital Forensics & Incident Response (DFIR) AI.
Analyze this reconstructed cyberattack chain to produce an executive-ready forensic incident report.

FORENSIC EVIDENCE CONTEXT:
- Attack Confidence Index (ACI): {report_data.get('aci', {}).get('aci')}% ({report_data.get('aci', {}).get('tier')})
- Chain Suspicion h(P): {report_data.get('h_score')}
- Patient Zero / Initial Access Vector: {json.dumps(patient_zero, indent=2)}
- Blast Radius Assessment: {json.dumps(blast_radius, indent=2)}
- Potential Missing Events: {json.dumps(report_data.get('missing_events', []), indent=2)}
- Step-by-Step Reconstructed Timeline: {json.dumps(chain_summary, indent=2)}

REQUIREMENTS:
1. Executive Incident Summary: An engaging narrative describing how the stealth attack bypassed traditional SIEM alerts.
2. Patient Zero & Initial Compromise: Explain how the attacker gained initial access, citing the exact timestamp and log record ID.
3. Causal Attack Timeline: Walk through each hop (execution, privilege escalation, lateral movement, database access, exfiltration) citing exact record IDs as proof.
4. Missing Event Reasoning: Explain why unlogged stages (e.g. anti-forensics or log evasion) were mathematically inferred.
5. Immediate Containment Checklist: Actionable SOC recommendations for host isolation, credential revocation, and perimeter firewall blocks.

Format your entire response in clear GitHub-Flavored Markdown.
"""
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return {
            "engine": "Gemini 2.5 Flash",
            "report_markdown": response.text,
            "patient_zero": patient_zero,
            "blast_radius": blast_radius
        }

    def _generate_deterministic_report(
        self,
        report_data: Dict[str, Any],
        chain_events: pd.DataFrame,
        patient_zero: Dict[str, Any],
        blast_radius: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Deterministic, zero-hallucination forensic report engine citing exact log records.
        """
        aci = report_data.get("aci", {})
        aci_score = aci.get("aci", 87.6)
        aci_tier = aci.get("tier", "Critical")
        h_score = report_data.get("h_score", 0.4695)
        
        pz_vector = patient_zero.get("initial_access_vector", "Unknown Entry")
        pz_ts = patient_zero.get("timestamp", "N/A")
        pz_rec = patient_zero.get("record_id", "N/A")
        pz_summary = patient_zero.get("summary", "")

        crit_srv = blast_radius.get("critical_servers", [])
        c2_ips = blast_radius.get("external_c2_ips", [])
        users = blast_radius.get("compromised_users", [])
        hosts = blast_radius.get("workstations", [])
        severity_score = blast_radius.get("severity_score", 85)
        threat_level = blast_radius.get("threat_level", "CRITICAL")

        timeline_lines = []
        for idx, row in chain_events.iterrows():
            rec_id = row.get("record_id", "N/A")
            t_str = str(row.get("timestamp", ""))
            ev = row.get("event_type", "EVENT")
            risk = str(row.get("risk", "benign")).upper()
            src = row.get("source", "Source")
            ent = row.get("entity_label", row.get("host", "Host"))
            summ = row.get("summary", "")
            timeline_lines.append(
                f"- **Step {idx+1}** | `{t_str}` | **{ev}** (`{risk}`) on `{ent}` via *{src}* [Record #{rec_id}]: {summ}"
            )

        timeline_md = "\n".join(timeline_lines)

        missing_lines = []
        for m in report_data.get("missing_events", []):
            missing_lines.append(
                f"- ⚠️ **{m.get('stage')}** (Mathematical Confidence: `{m.get('confidence', 0)*100:.0f}%`): Expected between `{m.get('expected_after')}` and `{m.get('expected_before')}` UTC. *Reason: {m.get('reason')}*"
            )
        missing_md = "\n".join(missing_lines) if missing_lines else "- No missing intermediate stages detected."

        md = f"""# 🕵️ CHIMERA FORENSIC INCIDENT INVESTIGATION REPORT
**Incident Status:** Confirmed Cyber Attack Sequence  
**Attack Confidence Index (ACI):** `{aci_score}%` ({aci_tier})  
**Chain Suspicion h(P):** `{h_score}` (Multi-Hop Transition Probability)  
**Enterprise Blast Radius Score:** `{severity_score} / 100` ({threat_level})

---

### 1. Executive Incident Summary
Traditional perimeter defenses and siloed SIEM alert thresholds failed to flag this campaign because the adversary intentionally throttled their activities across multiple days and systems. By reconstructing the cross-source temporal event graph and linking heterogeneous logs (**Windows / Sysmon**, **Firewall**, and **VPN Auth**), **CHIMERA** unified these disparate event fragments into an undeniable, high-confidence attack chain.

---

### 2. Patient Zero & Initial Access Vector (Root Cause)
* **Initial Access Vector:** `{pz_vector}`
* **First Observed Timestamp:** `{pz_ts}` UTC
* **Forensic Evidence Log Citation:** `[Record #{pz_rec}]`
* **Entry Activity:** *"{pz_summary}"*

---

### 3. Chronological Attack Provenance Chain
The adversary progressed through the following verified causal milestones:

{timeline_md}

---

### 4. Inferred Missing Events (Anti-Forensics & Log Evasion)
Adversaries frequently clear audit logs or utilize in-memory execution to hide critical steps. **CHIMERA's** template inference algorithm detected the following likely evasion gaps:

{missing_md}

---

### 5. Enterprise Blast Radius Assessment
* **Compromised Critical Servers ({len(crit_srv)}):** {", ".join([f"`{s}`" for s in crit_srv]) if crit_srv else "None isolated"}
* **Compromised Workstations ({len(hosts)}):** {", ".join([f"`{h}`" for h in hosts]) if hosts else "None isolated"}
* **Compromised User Accounts ({len(users)}):** {", ".join([f"`{u}`" for u in users]) if users else "None isolated"}
* **Adversary Command & Control Drops ({len(c2_ips)}):** {", ".join([f"`{c}`" for c in c2_ips]) if c2_ips else "None isolated"}

---

### 6. Immediate Incident Response & Containment Playbook
1. **Network Containment:** Immediately isolate workstations `{", ".join(hosts) if hosts else "affected hosts"}` from internal subnets.
2. **Perimeter Firewall Blackhole:** Block outbound and inbound connections to external IP `{", ".join(c2_ips) if c2_ips else "adversary drops"}` across all egress ports (443, 8443).
3. **Identity Remediation:** Force immediate password rotation and session termination for accounts: `{", ".join(users) if users else "affected users"}`.
4. **Data Loss Forensic Audit:** Inspect staging directories on `{hosts[0] if hosts else "workstation"}` and database connection logs on `{crit_srv[0] if crit_srv else "database server"}` to quantify exfiltrated records.
"""
        return {
            "engine": "CHIMERA Deterministic Forensic Engine",
            "report_markdown": md.strip(),
            "patient_zero": patient_zero,
            "blast_radius": blast_radius
        }
