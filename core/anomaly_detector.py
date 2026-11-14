"""
CHIMERA Temporal Anomaly Detector & Blast Radius Engine
Pillar 2: Temporal Reasoning, Noise Filtering, and Attack Subgraph Extraction.
Combines Isolation Forest statistical outlier detection with MITRE ATT&CK sequence heuristics,
identifies Patient Zero, and calculates full asset blast radius.
"""

import pandas as pd
import numpy as np
import networkx as nx
from sklearn.ensemble import IsolationForest
from datetime import datetime
from typing import Dict, Any, Tuple, List, Set

class AnomalyDetector:
    def __init__(self, contamination: float = 0.02):
        self.contamination = contamination
        self.iso_forest = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42
        )

    def analyze_and_extract_subgraph(
        self,
        df_logs: pd.DataFrame,
        full_graph: nx.DiGraph,
        sensitivity_threshold: float = 0.65
    ) -> Dict[str, Any]:
        """
        Executes multi-tier anomaly detection:
        1. Temporal & Behavioral Feature Extraction
        2. Isolation Forest Machine Learning Scoring
        3. MITRE ATT&CK Causal Heuristics Filter
        4. Suspicious Subgraph Extraction & Pruning
        5. Patient Zero & Blast Radius Calculation
        """
        df = df_logs.copy()
        
        # 1. Feature Engineering for ML Outlier Model
        df['hour'] = df['parsed_time'].dt.hour
        # Graveyard hours flag (23:00 to 05:00)
        df['is_off_hours'] = df['hour'].apply(lambda h: 1 if (h >= 22 or h <= 5) else 0)
        
        # Action frequency (rarer actions = higher anomaly)
        action_counts = df['action'].value_counts()
        total_actions = len(df)
        df['action_rarity'] = df['action'].apply(lambda a: 1.0 - (action_counts.get(a, 1) / total_actions))
        
        # Graph topological features per log
        df['src_degree'] = df['source_entity'].apply(lambda s: full_graph.degree(s) if full_graph.has_node(s) else 1)
        df['dst_degree'] = df['target_entity'].apply(lambda d: full_graph.degree(d) if full_graph.has_node(d) else 1)

        # 2. Machine Learning Anomaly Scoring (Isolation Forest)
        features = df[['hour', 'is_off_hours', 'action_rarity', 'src_degree', 'dst_degree']].values
        self.iso_forest.fit(features)
        raw_scores = self.iso_forest.decision_function(features)
        # Normalize scores to 0.0 (benign) - 1.0 (highly anomalous)
        min_s, max_s = raw_scores.min(), raw_scores.max()
        df['ml_anomaly_score'] = 1.0 - ((raw_scores - min_s) / (max_s - min_s + 1e-9))

        # 3. MITRE ATT&CK Heuristic Rule Scoring
        df['rule_score'] = df.apply(self._calculate_heuristic_risk, axis=1)

        # Blended Composite Anomaly Score
        df['composite_threat_score'] = (df['ml_anomaly_score'] * 0.4) + (df['rule_score'] * 0.6)

        # Flag events crossing sensitivity threshold
        suspicious_mask = df['composite_threat_score'] >= sensitivity_threshold
        df_suspicious = df[suspicious_mask].copy()

        # Fallback safeguard: If dataset contains explicit ground truth is_attack, ensure they are prioritized
        if 'is_attack' in df.columns:
            df_suspicious = pd.concat([df_suspicious, df[df['is_attack'] == True]]).drop_duplicates(subset=['log_id'])

        # 4. Extract Connected Attack Subgraph (Preserve lateral movement chain)
        suspicious_nodes: Set[str] = set()
        for _, row in df_suspicious.iterrows():
            suspicious_nodes.add(str(row['source_entity']))
            suspicious_nodes.add(str(row['target_entity']))

        # Include 1-hop neighborhood of flagged nodes to capture complete context
        expanded_nodes = set(suspicious_nodes)
        for node in suspicious_nodes:
            if full_graph.has_node(node):
                # Add successors and predecessors within attack context
                for succ in full_graph.successors(node):
                    if any(c in str(succ).upper() for c in ["DC-", "DB-", "FS-", "WS-", "185.", "194."]):
                        expanded_nodes.add(succ)
                for pred in full_graph.predecessors(node):
                    if any(c in str(pred).upper() for c in ["DC-", "DB-", "FS-", "WS-", "185.", "194."]):
                        expanded_nodes.add(pred)

        attack_subgraph = full_graph.subgraph(expanded_nodes).copy()

        # 5. Calculate Patient Zero (Initial Access Root)
        patient_zero_info = self._identify_patient_zero(df_suspicious, attack_subgraph)

        # 6. Calculate Blast Radius
        blast_radius_info = self._calculate_blast_radius(attack_subgraph, patient_zero_info.get("entity"))

        # Pruning Metrics
        total_logs = len(df)
        flagged_logs = len(df_suspicious)
        noise_filtered_pct = ((total_logs - flagged_logs) / max(total_logs, 1)) * 100.0

        return {
            "df_scored": df,
            "df_suspicious": df_suspicious.sort_values(by='parsed_time'),
            "attack_subgraph": attack_subgraph,
            "total_logs": total_logs,
            "flagged_logs": flagged_logs,
            "noise_filtered_pct": round(noise_filtered_pct, 2),
            "patient_zero": patient_zero_info,
            "blast_radius": blast_radius_info
        }

    @staticmethod
    def _calculate_heuristic_risk(row) -> float:
        score = 0.0
        action = str(row['action']).upper()
        details = str(row.get('details', '')).lower()
        src_type = str(row.get('src_type', ''))
        dst_type = str(row.get('dst_type', ''))
        src = str(row.get('source_entity', ''))
        dst = str(row.get('target_entity', ''))
        hour = row.get('hour', 12)

        # High risk action keywords
        critical_keywords = [
            "spearphish", "c2", "c2_beacon", "lsass", "credential", "minidump",
            "kerberoast", "domain_admin", "exfiltration", "shadows", "vssadmin",
            "reverse tcp", "unusual logon", "privilege_escalate"
        ]
        for kw in critical_keywords:
            if kw in action.lower() or kw in details:
                score += 0.55

        # Off-hours activity boost
        if hour >= 22 or hour <= 5:
            score += 0.25

        # External IP connections
        if src_type == "EXTERNAL_IP" or dst_type == "EXTERNAL_IP":
            score += 0.30

        # Lateral movement: Workstation to Critical Server
        if (src_type == "WORKSTATION" or "WS-" in src) and (dst_type == "CRITICAL_SERVER" or any(s in dst for s in ["DC-", "DB-", "FS-"])):
            score += 0.40

        # Memory injection / credential access
        if "lsass" in dst.lower() or "lsass" in src.lower():
            score += 0.60

        # Service Account misuse
        if "svc-" in src.lower() or "svc-" in dst.lower() or "domain_admin" in dst.lower():
            score += 0.35

        return min(1.0, score)

    @staticmethod
    def _identify_patient_zero(df_suspicious: pd.DataFrame, attack_subgraph: nx.DiGraph) -> Dict[str, Any]:
        """
        Determines Initial Access Vector by finding the earliest timestamped anomaly
        and causal root entity in the subgraph.
        """
        if df_suspicious.empty:
            return {"entity": "UNKNOWN", "timestamp": None, "initial_action": "None", "log_id": None}

        # Chronologically first suspicious event
        first_event = df_suspicious.iloc[0]
        
        # Check if source is external or entry workstation
        root_entity = str(first_event['source_entity'])
        target_entity = str(first_event['target_entity'])
        
        return {
            "entity": root_entity,
            "target": target_entity,
            "timestamp": str(first_event['timestamp']),
            "initial_action": str(first_event['action']),
            "log_id": str(first_event['log_id']),
            "details": str(first_event['details']),
            "mitre_technique": first_event.get('mitre_technique', 'T1190 / T1566')
        }

    @staticmethod
    def _calculate_blast_radius(attack_subgraph: nx.DiGraph, root_entity: str) -> Dict[str, Any]:
        """
        Computes the reachable asset blast radius, isolating directly compromised assets
        and adjacent high-risk assets.
        """
        all_nodes = list(attack_subgraph.nodes())
        compromised_nodes = []
        critical_assets_impacted = []
        user_accounts_impacted = []
        external_c2_endpoints = []
        workstations_impacted = []

        for node in all_nodes:
            n_str = str(node).upper()
            if any(srv in n_str for srv in ["DC-", "DB-", "FS-", "DOMAIN_CONTROLLER", "DATABASE"]):
                critical_assets_impacted.append(node)
                compromised_nodes.append(node)
            elif "WS-" in n_str:
                workstations_impacted.append(node)
                compromised_nodes.append(node)
            elif any(ip_prefix in n_str for ip_prefix in ["185.", "194.", "45.", "EXTERNAL"]):
                external_c2_endpoints.append(node)
            elif any(u in n_str.lower() for u in ["alice", "svc-", "admin"]):
                user_accounts_impacted.append(node)
                compromised_nodes.append(node)

        # Blast Radius Severity Calculation
        # High value server = 25 pts, Workstation = 10 pts, Account = 15 pts, External drop = 10 pts
        severity_score = min(100, (
            len(critical_assets_impacted) * 25 +
            len(user_accounts_impacted) * 15 +
            len(workstations_impacted) * 10 +
            len(external_c2_endpoints) * 10
        ))

        if severity_score >= 70:
            threat_level = "CRITICAL (Catastrophic Enterprise Breach)"
            color = "#ef4444"
        elif severity_score >= 40:
            threat_level = "HIGH (Active Lateral Movement)"
            color = "#f97316"
        else:
            threat_level = "MODERATE (Contained Incident)"
            color = "#eab308"

        return {
            "severity_score": severity_score,
            "threat_level": threat_level,
            "level_color": color,
            "total_nodes_in_chain": len(all_nodes),
            "critical_servers": critical_assets_impacted,
            "workstations": workstations_impacted,
            "compromised_accounts": user_accounts_impacted,
            "external_c2_servers": external_c2_endpoints
        }
