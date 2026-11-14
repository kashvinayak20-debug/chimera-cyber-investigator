"""
Stage 5 - Cross-Source Event Graph (Sec. 3.6).

Every extracted event is a node.  Directed edges go forward in time:
  same_entity  - both events belong to the same resolved entity and occur within
                 `same_entity_window_min`
  temporal     - different entities but the same user, within `temporal_window_min`
Each edge carries a transition weight alpha in (0,1] from config.TRANSITION_WEIGHTS
(explicit pairs) or config.DEFAULT_TRANSITION (by stage order).  The graph is a
DAG because edges only point to later events.
"""
from __future__ import annotations

import networkx as nx
import pandas as pd

from .config import DEFAULT_TRANSITION, EVENT_CATALOG, STAGE_INDEX, TRANSITION_WEIGHTS, Settings


def transition_weight(t_from: str, t_to: str) -> float:
    """alpha_i: how strongly event type t_from empirically precedes t_to."""
    if (t_from, t_to) in TRANSITION_WEIGHTS:
        return TRANSITION_WEIGHTS[(t_from, t_to)]
    s1, s2 = STAGE_INDEX[EVENT_CATALOG[t_from][0]], STAGE_INDEX[EVENT_CATALOG[t_to][0]]
    if s2 > s1:
        return DEFAULT_TRANSITION["forward"]
    if s2 == s1:
        return DEFAULT_TRANSITION["same"]
    return DEFAULT_TRANSITION["backward"]


def build_graph(events: pd.DataFrame, settings: Settings | None = None) -> nx.DiGraph:
    settings = settings or Settings()
    G = nx.DiGraph()
    if events.empty:
        return G
    ev = events.sort_values(["timestamp", "event_id"]).to_dict("records")
    for r in ev:
        G.add_node(int(r["event_id"]), **{k: r[k] for k in (
            "timestamp", "source", "event_type", "stage", "risk", "summary",
            "host", "user", "entity_id", "entity_label")})

    w_same = pd.Timedelta(minutes=settings.same_entity_window_min)
    w_temp = pd.Timedelta(minutes=settings.temporal_window_min)
    w_max = max(w_same, w_temp)
    for i, a in enumerate(ev):
        for b in ev[i + 1:]:
            dt = b["timestamp"] - a["timestamp"]
            if dt > w_max:
                break                                    # events are time-sorted
            kind = None
            if a["entity_id"] is not None and a["entity_id"] == b["entity_id"] and dt <= w_same:
                kind = "same_entity"
            elif (a["user"] and b["user"] and a["user"] == b["user"]
                  and a["entity_id"] != b["entity_id"] and dt <= w_temp):
                kind = "temporal"
            if kind is None:
                continue
            G.add_edge(int(a["event_id"]), int(b["event_id"]), kind=kind,
                       weight=transition_weight(a["event_type"], b["event_type"]),
                       gap_min=round(dt.total_seconds() / 60, 2))
    return G


def graph_summary(G: nx.DiGraph) -> dict:
    kinds = {}
    for _, _, d in G.edges(data=True):
        kinds[d["kind"]] = kinds.get(d["kind"], 0) + 1
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "edges_by_kind": kinds}
