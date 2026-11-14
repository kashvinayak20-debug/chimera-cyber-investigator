"""
CHIMERA Graph Reconstruction Engine
Constructs directed temporal provenance graphs using NetworkX from normalized security logs.
Exposes multi-hop lateral movement and process tree parent-child linkages.
"""

import networkx as nx
import pandas as pd
from typing import Dict, Any, List

class AttackGraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph_from_logs(self, df_logs: pd.DataFrame) -> nx.DiGraph:
        """
        Builds a directed graph where nodes are cyber entities and directed edges are observed actions.
        """
        self.graph.clear()
        
        for _, row in df_logs.iterrows():
            src = str(row['source_entity'])
            dst = str(row['target_entity'])
            src_type = row.get('src_type', 'UNKNOWN')
            dst_type = row.get('dst_type', 'UNKNOWN')
            
            # Add Source Node if not exists
            if not self.graph.has_node(src):
                self.graph.add_node(
                    src,
                    entity_type=src_type,
                    label=src,
                    first_seen=row['timestamp'],
                    last_seen=row['timestamp'],
                    event_count=0
                )
            
            # Add Target Node if not exists
            if not self.graph.has_node(dst):
                self.graph.add_node(
                    dst,
                    entity_type=dst_type,
                    label=dst,
                    first_seen=row['timestamp'],
                    last_seen=row['timestamp'],
                    event_count=0
                )
                
            # Update Node event stats
            self.graph.nodes[src]['event_count'] += 1
            self.graph.nodes[dst]['event_count'] += 1
            self.graph.nodes[src]['last_seen'] = row['timestamp']
            self.graph.nodes[dst]['last_seen'] = row['timestamp']

            # Edge properties
            edge_key = (src, dst)
            action = str(row['action'])
            log_id = str(row.get('log_id', ''))
            timestamp = str(row['timestamp'])
            details = str(row.get('details', ''))
            is_attack = bool(row.get('is_attack', False))
            threat_stage = str(row.get('threat_stage', 'BENIGN'))

            # For DiGraph with multiple events between same nodes, accumulate event list
            if self.graph.has_edge(src, dst):
                self.graph[src][dst]['events'].append({
                    "log_id": log_id,
                    "action": action,
                    "timestamp": timestamp,
                    "details": details,
                    "is_attack": is_attack,
                    "threat_stage": threat_stage
                })
                self.graph[src][dst]['weight'] += 1
                if is_attack:
                    self.graph[src][dst]['is_attack'] = True
            else:
                self.graph.add_edge(
                    src,
                    dst,
                    action=action,
                    timestamp=timestamp,
                    log_id=log_id,
                    details=details,
                    weight=1,
                    is_attack=is_attack,
                    threat_stage=threat_stage,
                    events=[{
                        "log_id": log_id,
                        "action": action,
                        "timestamp": timestamp,
                        "details": details,
                        "is_attack": is_attack,
                        "threat_stage": threat_stage
                    }]
                )
                
        return self.graph

    def get_graph_stats(self) -> Dict[str, Any]:
        """
        Calculates topological graph metrics.
        """
        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "strongly_connected_components": nx.number_strongly_connected_components(self.graph),
            "weakly_connected_components": nx.number_weakly_connected_components(self.graph)
        }

    @staticmethod
    def subgraph_to_json(subgraph: nx.DiGraph) -> Dict[str, Any]:
        """
        Serializes a subgraph into structured JSON for LLM forensic analysis.
        """
        nodes_list = []
        for n, data in subgraph.nodes(data=True):
            nodes_list.append({
                "id": n,
                "type": data.get("entity_type", "UNKNOWN"),
                "event_count": data.get("event_count", 1)
            })

        edges_list = []
        for u, v, data in subgraph.edges(data=True):
            for ev in data.get("events", []):
                edges_list.append({
                    "source": u,
                    "target": v,
                    "action": ev.get("action"),
                    "timestamp": ev.get("timestamp"),
                    "log_id": ev.get("log_id"),
                    "details": ev.get("details"),
                    "threat_stage": ev.get("threat_stage", "UNKNOWN")
                })
                
        # Sort edges chronologically
        edges_list = sorted(edges_list, key=lambda x: x.get("timestamp", ""))

        return {
            "node_count": len(nodes_list),
            "edge_count": len(edges_list),
            "nodes": nodes_list,
            "edges": edges_list
        }
