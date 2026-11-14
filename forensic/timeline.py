"""
Stage 6 - Timeline Reconstruction Engine (Sec. 3.6 Eq. 1, Sec. 3.7).

1. Chain search: for every event v and chain length k, find the path of k
   events ending at v that maximises the suspicion score
        h(P) = prod(alpha_i)                                    (Eq. 1)
   using a dynamic programme over the time-ordered DAG.  Only edges with
   alpha >= min_transition are followed and chains with h(P) < chain_threshold
   are discarded.  Deterministic, so every chain is explainable by its edges.
2. Filters: minimum length, at least one non-benign event; chains whose set of
   non-benign (evidence) events is contained in another chain's are removed,
   preferring more evidence, then the longer chain (more context), then h(P).
3. Template matching: the chain is compared with the multi-stage attack
   templates in config.ATTACK_TEMPLATES (stage coverage + chronological order).
4. Missing-event detection: template stages between the first and last matched
   stage that have no event are reported as potential missing events.
"""
from __future__ import annotations

import networkx as nx
import pandas as pd

from .config import ATTACK_TEMPLATES, Settings

MIN_MATCHED_STAGES = 2


# --------------------------------------------------------------------------- #
# Chain search
# --------------------------------------------------------------------------- #
def find_chains(G: nx.DiGraph, settings: Settings | None = None) -> list[dict]:
    settings = settings or Settings()
    if G.number_of_nodes() == 0:
        return []
    order = sorted(G.nodes, key=lambda n: (G.nodes[n]["timestamp"], n))
    # best[v][k] = (score, prev_node, gap) : best chain of exactly k events ending at v
    best: dict[int, dict[int, tuple[float, int | None, float]]] = {v: {1: (1.0, None, 0.0)} for v in order}

    for v in order:
        for u in G.predecessors(v):
            if G.nodes[u]["event_type"] == G.nodes[v]["event_type"]:
                continue                                  # no LOGIN -> LOGIN style steps
            edge = G[u][v]
            alpha, gap = edge["weight"], edge["gap_min"]
            if alpha < settings.min_transition:
                continue
            for k, (score, _, _) in list(best[u].items()):
                if k + 1 > settings.max_chain_length:
                    continue
                new_score = score * alpha
                if new_score < settings.chain_threshold:
                    continue
                cur = best[v].get(k + 1)
                # tie-break on smaller time gap -> more temporally coherent chain
                if cur is None or new_score > cur[0] or (new_score == cur[0] and gap < cur[2]):
                    best[v][k + 1] = (new_score, u, gap)

    candidates = []
    for v in order:
        for k, (score, _, _) in best[v].items():
            if k < settings.min_chain_length:
                continue
            path, node, kk = [], v, k
            while node is not None:
                path.append(node)
                _, prev, _ = best[node][kk]
                node, kk = prev, kk - 1
            path.reverse()
            evidence = frozenset(n for n in path if G.nodes[n]["risk"] != "benign")
            if not evidence:
                continue                                  # no attack evidence at all
            candidates.append({"events": path, "h": round(score, 4), "length": k, "_evidence": evidence})

    # Deduplicate on evidence: most evidence first, then longest (most context), then highest h(P).
    candidates.sort(key=lambda c: (-len(c["_evidence"]), -c["length"], -c["h"]))
    kept: list[dict] = []
    for c in candidates:
        if any(c["_evidence"] <= k["_evidence"] for k in kept):
            continue
        kept.append(c)
        if len(kept) >= settings.max_chains:
            break
    for i, c in enumerate(kept, start=1):
        c.pop("_evidence")
        c["chain_id"] = f"C{i:02d}"
        c["edges"] = [{"from": a, "to": b, "alpha": G[a][b]["weight"], "kind": G[a][b]["kind"],
                       "gap_min": G[a][b]["gap_min"]} for a, b in zip(c["events"], c["events"][1:])]
    return kept


# --------------------------------------------------------------------------- #
# Template matching and missing events
# --------------------------------------------------------------------------- #
def match_template(chain_df: pd.DataFrame) -> dict:
    """
    For each template, greedily assign the earliest unused chain event whose type
    is an indicator of the stage.  Best template = most matched stages, then
    highest coverage.  Returns coverage, order score and M_pat = coverage * order.
    A multi-stage pattern needs at least MIN_MATCHED_STAGES matched stages;
    below that M_pat is 0 (a single matching event is not a pattern).
    """
    rows = chain_df.sort_values("timestamp").to_dict("records")
    results = []
    for name, stages in ATTACK_TEMPLATES.items():
        used, matched = set(), {}
        for stage, indicators in stages:
            for r in rows:
                if r["event_id"] not in used and r["event_type"] in indicators:
                    matched[stage] = r
                    used.add(r["event_id"])
                    break
        coverage = len(matched) / len(stages)
        seq = [matched[s]["timestamp"] for s, _ in stages if s in matched]
        pairs = [(a, b) for i, a in enumerate(seq) for b in seq[i + 1:]]
        order = sum(1 for a, b in pairs if a <= b) / len(pairs) if pairs else 1.0
        m_pat = coverage * order if len(matched) >= MIN_MATCHED_STAGES else 0.0
        results.append({"template": name, "stages": [s for s, _ in stages],
                        "matched": {s: r["event_id"] for s, r in matched.items()},
                        "matched_count": len(matched), "coverage": round(coverage, 3),
                        "order_score": round(order, 3), "m_pat": round(m_pat, 3),
                        "note": "" if len(matched) >= MIN_MATCHED_STAGES else
                                f"fewer than {MIN_MATCHED_STAGES} stages matched - not a multi-stage pattern"})
    return max(results, key=lambda x: (x["matched_count"], x["coverage"], x["order_score"]))


def detect_missing_events(match: dict, chain_df: pd.DataFrame) -> list[dict]:
    """
    A template stage with no event, located between two matched stages, is a
    potential missing event.  Confidence = 0.5*coverage + 0.25*[previous stage
    matched] + 0.25*[next stage matched].
    """
    stages, matched = match["stages"], match["matched"]
    idx = [i for i, s in enumerate(stages) if s in matched]
    if len(idx) < 2:
        return []
    ts = chain_df.set_index("event_id")["timestamp"]
    missing = []
    for i in range(idx[0] + 1, idx[-1]):
        stage = stages[i]
        if stage in matched:
            continue
        prev_ok, next_ok = stages[i - 1] in matched, stages[i + 1] in matched
        conf = 0.5 * match["coverage"] + 0.25 * prev_ok + 0.25 * next_ok
        before = max((ts[matched[s]] for s in stages[:i] if s in matched), default=None)
        after = min((ts[matched[s]] for s in stages[i + 1:] if s in matched), default=None)
        missing.append({"stage": stage, "confidence": round(conf, 3),
                        "expected_after": before, "expected_before": after,
                        "reason": f"Template '{match['template']}' expects {stage} between "
                                  f"{stages[i-1]} and {stages[i+1]}; no matching event was found."})
    return missing


def reconstruct_timeline(chain: dict, events: pd.DataFrame) -> pd.DataFrame:
    """Chronologically ordered events of a chain with their step numbers."""
    df = events[events["event_id"].isin(chain["events"])].sort_values(["timestamp", "event_id"]).copy()
    df.insert(0, "step", range(1, len(df) + 1))
    return df.reset_index(drop=True)
