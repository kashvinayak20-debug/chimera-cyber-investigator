"""
Pipeline orchestration: runs the seven stages in order and returns everything
each Streamlit page needs.

    Log Collection -> Log Normalization -> Event Extraction -> Entity Resolution
    -> Cross-Source Event Graph -> Timeline Reconstruction -> Investigation Report
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import networkx as nx
import pandas as pd

from .collection import RawLog, load_directory
from .config import Settings
from .entity_resolution import assign_entities, entities_frame, links_frame, resolve_entities
from .extraction import extract_events
from .graph_builder import build_graph, graph_summary
from .normalization import normalize_logs
from .report import build_report
from .timeline import detect_missing_events, find_chains, match_template, reconstruct_timeline

SAMPLE_DIR = Path(__file__).resolve().parents[1] / "data" / "samples"


@dataclass
class PipelineResult:
    run_name: str
    settings: Settings
    normalized: pd.DataFrame
    events: pd.DataFrame
    entities: pd.DataFrame
    links: pd.DataFrame
    graph: nx.DiGraph
    chains: list[dict]
    reports: list[dict]                 # one per chain, sorted by ACI descending
    stats: dict = field(default_factory=dict)
    run_id: int | None = None

    @property
    def raw_count(self) -> int:
        collected = self.stats.get("collected", {})
        if collected:
            return sum(v.get("lines", 0) for v in collected.values())
        return len(self.normalized)

    @property
    def best_report(self) -> dict | None:
        return self.reports[0] if self.reports else None

    def chain(self, chain_id: str) -> dict | None:
        return next((c for c in self.chains if c["chain_id"] == chain_id), None)

    def report(self, chain_id: str) -> dict | None:
        return next((r for r in self.reports if r["chain_id"] == chain_id), None)

    def chain_events(self, chain_id: str) -> pd.DataFrame:
        c = self.chain(chain_id)
        return reconstruct_timeline(c, self.events) if c else self.events.iloc[0:0]


def run_pipeline(raw_logs: list[RawLog], settings: Settings | None = None, run_name: str = "run") -> PipelineResult:
    settings = settings or Settings()
    stats = {"collected": {lg.name: {"source": lg.source, "lines": lg.line_count} for lg in raw_logs}}

    # 2. normalization
    normalized, norm_stats = normalize_logs(raw_logs, settings)
    stats["normalized"] = norm_stats

    # 3. event extraction
    events = extract_events(normalized, settings)
    stats["events"] = {"total": len(events),
                       "by_type": events["event_type"].value_counts().to_dict() if len(events) else {},
                       "by_risk": events["risk"].value_counts().to_dict() if len(events) else {}}

    # 4. entity resolution (uses all normalized records, not only extracted events)
    resolver = resolve_entities(normalized, settings)
    events = assign_entities(events, resolver)
    entities, links = entities_frame(resolver), links_frame(resolver)
    stats["entities"] = {"total": len(entities), "links": len(links),
                         "links_by_rule": links["rule"].value_counts().to_dict() if len(links) else {}}

    # 5. graph
    G = build_graph(events, settings)
    stats["graph"] = graph_summary(G)

    # 6. timeline reconstruction
    chains = find_chains(G, settings)
    stats["chains"] = len(chains)

    # 7. investigation reports
    reports = []
    for c in chains:
        chain_df = reconstruct_timeline(c, events)
        match = match_template(chain_df)
        missing = detect_missing_events(match, chain_df)
        reports.append(build_report(c, chain_df, match, missing, settings))
    reports.sort(key=lambda r: (-r["aci"]["aci"], -r["h_score"]))
    # re-label chains by rank so C01 is always the top-ranked chain
    rank = {r["chain_id"]: f"C{i:02d}" for i, r in enumerate(reports, start=1)}
    for c in chains:
        c["chain_id"] = rank[c["chain_id"]]
    for r in reports:
        r["chain_id"] = rank[r["chain_id"]]
    chains.sort(key=lambda c: c["chain_id"])

    return PipelineResult(run_name=run_name, settings=settings, normalized=normalized, events=events,
                          entities=entities, links=links, graph=G, chains=chains, reports=reports, stats=stats)


def run_on_samples(settings: Settings | None = None, sample_dir: Path = SAMPLE_DIR) -> PipelineResult:
    return run_pipeline(load_directory(sample_dir), settings, run_name="sample logs")


if __name__ == "__main__":                       # python -m forensic.pipeline
    from .report import report_to_markdown
    res = run_on_samples()
    print(f"records={res.stats['normalized']['total']} events={len(res.events)} "
          f"entities={len(res.entities)} graph={res.stats['graph']} chains={len(res.chains)}")
    if res.best_report:
        print(report_to_markdown(res.best_report))
