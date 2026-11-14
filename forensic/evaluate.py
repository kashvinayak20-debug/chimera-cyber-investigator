"""
Evaluation of a pipeline result against a ground-truth attack chain
(data/samples/ground_truth.json).  Metrics follow Table 2 of the paper where
they can be computed from a single labelled chain:

  Timeline Completeness      - ground-truth events recovered in the top chain
  Correlation Precision      - top-chain events that belong to the ground truth
  Timeline Reconstruction Accuracy - recovered events in the correct order
  Missing-event detection    - whether the injected missing stage was flagged

    python -m forensic.evaluate
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .pipeline import SAMPLE_DIR, PipelineResult, run_on_samples

TOLERANCE = pd.Timedelta(minutes=1)


def evaluate(result: PipelineResult, ground_truth: dict) -> dict:
    truth = ground_truth["attack_chain"]
    rep = result.best_report
    if rep is None:
        return {"timeline_completeness": 0.0, "correlation_precision": 0.0, "reconstruction_accuracy": 0.0,
                "missing_stage_detected": False, "chain_id": None}
    chain = result.chain_events(rep["chain_id"])
    matched_steps = []
    for gt in truth:
        ts = pd.Timestamp(gt["timestamp"])
        hit = chain[(chain["source"] == gt["source"]) & (chain["event_type"] == gt["event_type"])
                    & ((chain["timestamp"] - ts).abs() <= TOLERANCE)]
        matched_steps.append(int(hit["step"].iloc[0]) if len(hit) else None)
    found = [s for s in matched_steps if s is not None]
    ordered = all(a < b for a, b in zip(found, found[1:]))
    return {
        "chain_id": rep["chain_id"],
        "timeline_completeness": round(len(found) / len(truth), 3),
        "correlation_precision": round(len(set(found)) / len(chain), 3) if len(chain) else 0.0,
        "reconstruction_accuracy": round(len(found) / len(truth), 3) if ordered else 0.0,
        "missing_stage_detected": any(m["stage"] == ground_truth.get("missing_stage") for m in rep["missing_events"]),
        "aci": rep["aci"]["aci"], "tier": rep["aci"]["tier"],
        "matched_steps": matched_steps,
    }


if __name__ == "__main__":
    gt = json.loads((Path(SAMPLE_DIR) / "ground_truth.json").read_text())
    print(json.dumps(evaluate(run_on_samples(), gt), indent=2))
