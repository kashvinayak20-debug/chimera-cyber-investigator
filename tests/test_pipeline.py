import json

import pytest

from forensic.collection import load_directory
from forensic.config import Settings
from forensic.evaluate import evaluate
from forensic.graph_builder import transition_weight
from forensic.pipeline import SAMPLE_DIR, run_on_samples, run_pipeline
from forensic.sample_data import generate
from forensic.storage import load_run, save_run


@pytest.fixture(scope="module")
def result():
    return run_on_samples()


def test_transition_weights():
    assert transition_weight("POWERSHELL_EXEC", "CREDENTIAL_DUMP") == 0.95
    assert transition_weight("LOGIN", "FILE_CREATE") == 0.55          # forward stage, default
    assert transition_weight("FILE_CREATE", "LOGIN") == 0.15          # backward stage


def test_top_chain_is_the_injected_attack(result):
    rep = result.best_report
    types = [s["event_type"] for s in rep["steps"]]
    assert types == ["LOGIN", "POWERSHELL_EXEC", "CREDENTIAL_DUMP", "VPN_LOGIN", "DB_ACCESS", "ARCHIVE_CREATED", "EXTERNAL_UPLOAD"]
    assert rep["entities"] == ["PC-001"] and rep["users"] == ["jsmith"]
    assert rep["aci"]["tier"] in ("High", "Critical")
    assert {e["source"] for e in rep["evidence_sources"]} == {"windows_sysmon", "firewall", "vpn_auth"}
    assert any(m["stage"] == "PRIVILEGE_ESCALATION" for m in rep["missing_events"])
    assert any("Block attacker IP 203.0.113.50" in r for r in rep["recommendations"])
    assert abs(sum(rep["aci"]["contributions"].values()) - rep["aci"]["aci"]) < 0.2


def test_h_score_is_product_of_edge_alphas(result):
    c = result.chain(result.best_report["chain_id"])
    prod = 1.0
    for e in c["edges"]:
        prod *= e["alpha"]
    assert abs(prod - c["h"]) < 1e-3


def test_evaluation_against_ground_truth(result):
    gt = json.loads((SAMPLE_DIR / "ground_truth.json").read_text())
    m = evaluate(result, gt)
    assert m["timeline_completeness"] >= 0.85
    assert m["correlation_precision"] >= 0.85
    assert m["missing_stage_detected"]


def test_noise_chains_rank_below_attack(result):
    acis = [r["aci"]["aci"] for r in result.reports]
    assert acis == sorted(acis, reverse=True)
    assert all(r["aci"]["tier"] in ("Low", "Medium") for r in result.reports[1:])


def test_pipeline_is_robust_to_other_seeds(tmp_path):
    for seed in (1, 42):
        generate(seed, tmp_path / str(seed))
        res = run_pipeline(load_directory(tmp_path / str(seed)), Settings())
        gt = json.loads((tmp_path / str(seed) / "ground_truth.json").read_text())
        m = evaluate(res, gt)
        assert m["timeline_completeness"] >= 0.85, (seed, m)


def test_sqlite_roundtrip(result, tmp_path):
    db = tmp_path / "t.db"
    run_id = save_run(result, "test", db)
    loaded = load_run(run_id, db)
    assert len(loaded.events) == len(result.events)
    assert loaded.graph.number_of_edges() == result.graph.number_of_edges()
    assert loaded.best_report["aci"]["aci"] == result.best_report["aci"]["aci"]
    assert loaded.chain_events(loaded.best_report["chain_id"])["event_type"].tolist() == \
        result.chain_events(result.best_report["chain_id"])["event_type"].tolist()


def test_empty_input_does_not_crash():
    res = run_pipeline([], Settings())
    assert res.chains == [] and res.best_report is None
