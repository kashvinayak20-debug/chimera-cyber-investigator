"""
SQLite persistence for pipeline runs.

Tables: runs, normalized_events, extracted_events, entities, entity_links, chains.
A run can be reloaded later; the graph is rebuilt deterministically from the
stored events and settings.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "forensic.db"


def _json_default(o):
    if isinstance(o, (pd.Timestamp, datetime)):
        return o.strftime("%Y-%m-%d %H:%M:%S")
    if hasattr(o, "item"):
        return o.item()
    return str(o)


def _connect(db_path) -> sqlite3.Connection:
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(p)
    con.execute("""CREATE TABLE IF NOT EXISTS runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, created_at TEXT,
        settings_json TEXT, stats_json TEXT, reports_json TEXT)""")
    return con


def _frame_for_sql(df: pd.DataFrame, run_id: int) -> pd.DataFrame:
    out = df.copy()
    for c in out.columns:
        if pd.api.types.is_datetime64_any_dtype(out[c]):
            out[c] = out[c].dt.strftime("%Y-%m-%d %H:%M:%S")
        elif out[c].dtype == object:
            out[c] = out[c].map(lambda v: json.dumps(v, default=_json_default)
                                if isinstance(v, (list, dict)) else v)
    out.insert(0, "run_id", run_id)
    return out


def save_run(result, name: str, db_path=DEFAULT_DB) -> int:
    con = _connect(db_path)
    try:
        cur = con.execute("INSERT INTO runs(name, created_at, settings_json, stats_json, reports_json) VALUES (?,?,?,?,?)",
                          (name, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                           json.dumps(result.settings.to_dict()), json.dumps(result.stats, default=_json_default),
                           json.dumps(result.reports, default=_json_default)))
        run_id = cur.lastrowid
        _frame_for_sql(result.normalized, run_id).to_sql("normalized_events", con, if_exists="append", index=False)
        _frame_for_sql(result.events, run_id).to_sql("extracted_events", con, if_exists="append", index=False)
        _frame_for_sql(result.entities, run_id).to_sql("entities", con, if_exists="append", index=False)
        _frame_for_sql(result.links, run_id).to_sql("entity_links", con, if_exists="append", index=False)
        chains = pd.DataFrame([{"chain_id": c["chain_id"], "h": c["h"], "length": c["length"],
                                "events": json.dumps(c["events"]), "edges": json.dumps(c["edges"])}
                               for c in result.chains], columns=["chain_id", "h", "length", "events", "edges"])
        _frame_for_sql(chains, run_id).to_sql("chains", con, if_exists="append", index=False)
        con.commit()
        return run_id
    finally:
        con.close()


def list_runs(db_path=DEFAULT_DB) -> pd.DataFrame:
    con = _connect(db_path)
    try:
        return pd.read_sql("SELECT run_id, name, created_at FROM runs ORDER BY run_id DESC", con)
    finally:
        con.close()


def load_run(run_id: int | None = None, db_path=DEFAULT_DB):
    """Return a PipelineResult rebuilt from SQLite (latest run when run_id is None)."""
    from .config import Settings
    from .graph_builder import build_graph
    from .pipeline import PipelineResult

    con = _connect(db_path)
    try:
        q = "SELECT * FROM runs" + (" WHERE run_id=?" if run_id is not None else " ORDER BY run_id DESC LIMIT 1")
        row = con.execute(q, (run_id,) if run_id is not None else ()).fetchone()
        if row is None:
            return None
        run_id = row[0]
        settings = Settings.from_dict(json.loads(row[3]))

        def tbl(name):
            df = pd.read_sql(f"SELECT * FROM {name} WHERE run_id=?", con, params=(run_id,)).drop(columns=["run_id"])
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"])
            return df

        normalized, events = tbl("normalized_events"), tbl("extracted_events")
        entities, links, chains_df = tbl("entities"), tbl("entity_links"), tbl("chains")
        chains = [{"chain_id": r["chain_id"], "h": r["h"], "length": int(r["length"]),
                   "events": json.loads(r["events"]), "edges": json.loads(r["edges"])}
                  for r in chains_df.to_dict("records")]
        return PipelineResult(
            run_name=row[1], settings=settings, normalized=normalized, events=events, entities=entities,
            links=links, graph=build_graph(events, settings), chains=chains,
            reports=json.loads(row[5]), stats=json.loads(row[4]), run_id=run_id)
    finally:
        con.close()
