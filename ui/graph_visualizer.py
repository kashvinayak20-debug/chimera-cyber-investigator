"""CHIMERA Interactive Graph Visualizer
Renders clean, modern attack provenance graphs using PyVis.
Seamlessly integrates with both PipelineResult and custom NetworkX graphs.
"""

from pyvis.network import Network
import networkx as nx
import pandas as pd
from typing import Optional, Dict, Any

class GraphVisualizer:
    @staticmethod
    def render_pipeline_graph_html(
        pipeline_result,
        chain_id: Optional[str] = None,
        height: str = "560px",
        focus_chain: bool = True
    ) -> str:
        """
        Builds an interactive PyVis network directly from a forensic PipelineResult.
        Highlights the selected attack chain edges and entities with distinct colors.
        """
        net = Network(height=height, width="100%", directed=True, bgcolor="#0b0f19", font_color="#f9fafb")
        
        # Configure physics for clear, readable layout
        net.set_options("""
        {
          "nodes": {
            "font": {
              "size": 12,
              "face": "Inter, -apple-system, sans-serif",
              "color": "#f9fafb"
            },
            "borderWidth": 2
          },
          "edges": {
            "font": {
              "size": 10,
              "face": "Inter, -apple-system, sans-serif",
              "align": "middle",
              "color": "#9ca3af"
            },
            "arrows": {
              "to": { "enabled": true, "scaleFactor": 0.8 }
            },
            "smooth": {
              "type": "curvedCW",
              "roundness": 0.2
            }
          },
          "physics": {
            "forceAtlas2Based": {
              "gravitationalConstant": -60,
              "centralGravity": 0.015,
              "springLength": 130,
              "springConstant": 0.08
            },
            "maxVelocity": 30,
            "solver": "forceAtlas2Based",
            "stabilization": { "iterations": 100 }
          },
          "interaction": {
            "hover": true,
            "tooltipDelay": 80,
            "navigationButtons": true,
            "zoomView": true
          }
        }
        """)

        G = pipeline_result.graph
        selected_chain = pipeline_result.chain(chain_id) if chain_id else (pipeline_result.chains[0] if pipeline_result.chains else None)
        
        chain_nodes = set(selected_chain["events"]) if selected_chain else set()
        chain_edges = {(e["from"], e["to"]) for e in selected_chain.get("edges", [])} if selected_chain else set()

        nodes_to_draw = chain_nodes if (focus_chain and chain_nodes) else set(G.nodes())

        # Add Nodes
        for node in nodes_to_draw:
            if not G.has_node(node):
                continue
            data = G.nodes[node]
            ev_type = str(data.get("event_type", "EVENT"))
            risk = str(data.get("risk", "benign")).lower()
            source = str(data.get("source", "UNKNOWN"))
            entity = str(data.get("entity_label", "ASSET"))
            user = str(data.get("user", "user"))
            summary = str(data.get("summary", ""))
            ts = str(data.get("timestamp", ""))

            # Clean semantic colors
            if risk == "high" or ev_type in ["EXTERNAL_UPLOAD", "CREDENTIAL_DUMP"]:
                color = {"background": "#ef4444", "border": "#f87171", "highlight": {"background": "#dc2626", "border": "#fff"}}
                shape = "diamond"
                size = 26
            elif risk == "suspicious" or ev_type in ["POWERSHELL_EXEC", "DB_ACCESS", "ARCHIVE_CREATED", "PRIVILEGE_ESCALATION"]:
                color = {"background": "#f59e0b", "border": "#fbbf24", "highlight": {"background": "#d97706", "border": "#fff"}}
                shape = "dot"
                size = 22
            elif ev_type in ["LOGIN", "VPN_LOGIN", "LOGIN_REMOTE"]:
                color = {"background": "#3b82f6", "border": "#60a5fa", "highlight": {"background": "#2563eb", "border": "#fff"}}
                shape = "triangle"
                size = 20
            else:
                color = {"background": "#4b5563", "border": "#6b7280", "highlight": {"background": "#374151", "border": "#fff"}}
                shape = "dot"
                size = 16

            label = f"#{node} {ev_type}"
            tooltip = f"<b>Event #{node}: {ev_type}</b> ({risk.upper()})<br/>"
            tooltip += f"<b>Entity:</b> {entity} | <b>User:</b> {user}<br/>"
            tooltip += f"<b>Timestamp:</b> {ts}<br/>"
            tooltip += f"<b>Source:</b> {source}<br/>"
            tooltip += f"<i>{summary}</i>"

            net.add_node(node, label=label, title=tooltip, color=color, shape=shape, size=size)

        # Add Edges
        for u, v, data in G.edges(data=True):
            if u not in nodes_to_draw or v not in nodes_to_draw:
                continue

            is_in_chain = (u, v) in chain_edges
            kind = data.get("kind", "same_entity")
            alpha = data.get("alpha", 0.5)
            gap_min = data.get("gap_min", 0.0)

            if is_in_chain:
                edge_color = "#ef4444"
                edge_width = 3.0
            else:
                edge_color = "#374151"
                edge_width = 1.0

            tooltip = f"<b>Edge:</b> {G.nodes[u].get('event_type')} ➔ {G.nodes[v].get('event_type')}<br/>"
            tooltip += f"<b>Type:</b> {kind} | <b>Transition Weight α:</b> {alpha}<br/>"
            tooltip += f"<b>Time Gap:</b> {gap_min:.1f} min"

            net.add_edge(u, v, title=tooltip, color=edge_color, width=edge_width)

        return net.generate_html()

    @staticmethod
    def render_custom_subgraph_html(
        subgraph: nx.DiGraph,
        height: str = "560px"
    ) -> str:
        """Renders an extracted anomaly subgraph with clean modern styling."""
        net = Network(height=height, width="100%", directed=True, bgcolor="#0b0f19", font_color="#f9fafb")
        net.set_options("""
        {
          "nodes": {
            "font": { "size": 12, "face": "Inter, sans-serif", "color": "#f9fafb" },
            "borderWidth": 2
          },
          "edges": {
            "arrows": { "to": { "enabled": true, "scaleFactor": 0.8 } }
          },
          "physics": {
            "barnesHut": { "gravitationalConstant": -3000, "springLength": 120 }
          }
        }
        """)

        for node, data in subgraph.nodes(data=True):
            role = data.get("role", "context")
            if role == "patient_zero":
                color = {"background": "#f59e0b", "border": "#fbbf24"}
                shape = "star"
                size = 30
            elif role == "attacker_c2":
                color = {"background": "#ef4444", "border": "#f87171"}
                shape = "diamond"
                size = 28
            elif role == "internal_hop":
                color = {"background": "#3b82f6", "border": "#60a5fa"}
                shape = "dot"
                size = 22
            else:
                color = {"background": "#4b5563", "border": "#6b7280"}
                shape = "dot"
                size = 18

            label = str(node)
            title = f"<b>Entity:</b> {node}<br/><b>Role:</b> {role.upper()}"
            net.add_node(node, label=label, title=title, color=color, shape=shape, size=size)

        for u, v, data in subgraph.edges(data=True):
            action = data.get("action", "INTERACTION")
            is_attack = data.get("is_attack", False)
            color = "#ef4444" if is_attack else "#374151"
            width = 2.5 if is_attack else 1.0
            title = f"<b>Action:</b> {action}"
            net.add_edge(u, v, label=action, title=title, color=color, width=width)

        return net.generate_html()
