"""
Stage 7 - Explainable Investigation Engine (Sec. 3.8, Eq. 2).

    ACI(P) = w1*S_src(P) + w2*T_coh(P) + w3*R_ent(P) + w4*M_pat(P)

  S_src  diversity of independent log sources supporting the attack evidence
         (sources of non-benign events / all pipeline sources)
  T_coh  temporal coherence: mean gap score, 1.0 for gaps <= ideal, linear
         decay to 0.0 at max gap
  R_ent  mean confidence of the resolved entities in the chain
  M_pat  fit to the best multi-stage attack template (coverage * order)

Every component is returned with the numbers that produced it, so the index
is fully traceable to the log records behind it.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from .config import ACI_TIERS, RECOMMENDATIONS, RISK_ORDER, SOURCE_LABELS, SOURCES, Settings


def _val(v):
    """None for NaN/empty so values serialise and compare cleanly."""
    if v is None or (isinstance(v, float) and pd.isna(v)) or str(v).strip() == "":
        return None
    return v


def _gap_score(gap_min: float, ideal: float, maximum: float) -> float:
    if gap_min <= ideal:
        return 1.0
    if gap_min >= maximum:
        return 0.0
    return 1.0 - (gap_min - ideal) / (maximum - ideal)


def compute_aci(chain_df: pd.DataFrame, match: dict, settings: Settings | None = None) -> dict:
    settings = settings or Settings()
    w = settings.weights()
    df = chain_df.sort_values("timestamp")

    evidence = df[df["risk"] != "benign"]
    ev_sources = sorted(evidence["source"].unique().tolist())
    s_src = len(ev_sources) / len(SOURCES)

    gaps = [(b - a).total_seconds() / 60 for a, b in zip(df["timestamp"], df["timestamp"].iloc[1:])]
    gap_scores = [_gap_score(g, settings.coherence_ideal_gap_min, settings.coherence_max_gap_min) for g in gaps]
    t_coh = sum(gap_scores) / len(gap_scores) if gap_scores else 1.0

    ents = df.drop_duplicates("entity_id")
    r_ent = float(ents["entity_confidence"].mean()) if len(ents) else 1.0

    m_pat = match["m_pat"]

    components = {"S_src": s_src, "T_coh": t_coh, "R_ent": r_ent, "M_pat": m_pat}
    aci = sum(w[k] * components[k] for k in components) * 100
    tier, response = next((t, r) for lo, t, r in ACI_TIERS if aci >= lo)
    return {
        "aci": round(aci, 1), "tier": tier, "response": response,
        "weights": {k: round(v, 3) for k, v in w.items()},
        "components": {k: round(v, 3) for k, v in components.items()},
        "contributions": {k: round(w[k] * components[k] * 100, 1) for k in components},
        "explanation": {
            "S_src": f"{len(ev_sources)} of {len(SOURCES)} sources carry non-benign evidence: "
                     f"{', '.join(SOURCE_LABELS[s] for s in ev_sources) or 'none'}",
            "T_coh": f"gaps between steps (min): {[round(g, 1) for g in gaps]}; "
                     f"score 1.0 up to {settings.coherence_ideal_gap_min} min, 0.0 at {settings.coherence_max_gap_min} min",
            "R_ent": f"entities {ents['entity_label'].tolist()} with confidences "
                     f"{ents['entity_confidence'].round(3).tolist()}",
            "M_pat": f"template '{match['template']}': {match['matched_count']}/{len(match['stages'])} stages "
                     f"matched (coverage {match['coverage']}), order score {match['order_score']}"
                     + (f"; {match['note']}" if match.get("note") else ""),
        },
    }


def _fmt(template: str, r: dict) -> str:
    class _Safe(dict):
        def __missing__(self, k):
            return "?"
    vals = {k: (v if v is not None and not (isinstance(v, float) and pd.isna(v)) else "?") for k, v in r.items()}
    return template.format_map(_Safe(vals))


def recommendations_for(chain_df: pd.DataFrame) -> list[str]:
    """One recommendation per non-benign event type, ordered by severity then time."""
    seen, out = set(), []
    rows = chain_df.sort_values(["timestamp"]).to_dict("records")
    rows.sort(key=lambda r: -RISK_ORDER[r["risk"]])
    for r in rows:
        t = r["event_type"]
        if r["risk"] == "benign" or t in seen or t not in RECOMMENDATIONS:
            continue
        seen.add(t)
        out.append(_fmt(RECOMMENDATIONS[t], r))
    return out


def evidence_sources(chain_df: pd.DataFrame) -> list[dict]:
    out = []
    for src, grp in chain_df.groupby("source"):
        out.append({"source": src, "label": SOURCE_LABELS[src], "events": len(grp),
                    "record_ids": grp["record_id"].tolist()})
    return out


def build_report(chain: dict, chain_df: pd.DataFrame, match: dict, missing: list[dict],
                 settings: Settings | None = None) -> dict:
    aci = compute_aci(chain_df, match, settings)
    steps = []
    for r in chain_df.sort_values("timestamp").to_dict("records"):
        steps.append({
            "step": int(r["step"]), "event_id": int(r["event_id"]),
            "time": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"), "event_type": r["event_type"],
            "stage": r["stage"], "risk": r["risk"], "source": SOURCE_LABELS[r["source"]],
            "entity": _val(r["entity_label"]), "user": _val(r["user"]), "rule": r["rule"], "summary": r["summary"],
            "raw": _val(r["raw"]),
        })
    return {
        "chain_id": chain["chain_id"], "h_score": chain["h"], "length": chain["length"],
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "window": {"start": steps[0]["time"], "end": steps[-1]["time"]},
        "entities": sorted({s["entity"] for s in steps if s["entity"]}),
        "users": sorted({s["user"] for s in steps if s["user"]}),
        "aci": aci,
        "template": match,
        "missing_events": [{**m, "expected_after": m["expected_after"].strftime("%H:%M:%S") if m["expected_after"] is not None else None,
                            "expected_before": m["expected_before"].strftime("%H:%M:%S") if m["expected_before"] is not None else None}
                           for m in missing],
        "evidence_sources": evidence_sources(chain_df),
        "recommendations": recommendations_for(chain_df),
        "steps": steps,
        "edges": chain["edges"],
    }


def report_to_markdown(rep: dict) -> str:
    a = rep["aci"]
    lines = [f"# Investigation Report - chain {rep['chain_id']}", "",
             f"Generated: {rep['generated_at']}  ",
             f"Window: {rep['window']['start']} -> {rep['window']['end']} (UTC)  ",
             f"Entities: {', '.join(rep['entities'])}  ", f"Users: {', '.join(rep['users'])}", "",
             f"## Attack Confidence Index: {a['aci']}% ({a['tier']})", f"Suggested response: {a['response']}", "",
             "| Component | Value | Weight | Contribution | Explanation |", "|---|---|---|---|---|"]
    for k in a["components"]:
        lines.append(f"| {k} | {a['components'][k]} | {a['weights'][k]} | {a['contributions'][k]} | {a['explanation'][k]} |")
    lines += ["", f"Chain suspicion h(P) = {rep['h_score']} over {rep['length']} events", "",
              "## Reconstructed timeline", "", "| Step | Time (UTC) | Event | Risk | Source | Entity | Rule | Summary |",
              "|---|---|---|---|---|---|---|---|"]
    for s in rep["steps"]:
        lines.append(f"| {s['step']} | {s['time']} | {s['event_type']} | {s['risk']} | {s['source']} | {s['entity']} | {s['rule']} | {s['summary']} |")
    lines += ["", "## Potential missing events", ""]
    if rep["missing_events"]:
        for m in rep["missing_events"]:
            lines.append(f"- {m['stage']} (confidence {m['confidence']*100:.0f}%) expected between "
                         f"{m['expected_after']} and {m['expected_before']}: {m['reason']}")
    else:
        lines.append("- none")
    lines += ["", "## Evidence sources", ""]
    for e in rep["evidence_sources"]:
        lines.append(f"- {e['label']}: {e['events']} event(s), records {e['record_ids']}")
    lines += ["", "## Recommendations", ""] + [f"- {r}" for r in rep["recommendations"]]
    return "\n".join(lines)
