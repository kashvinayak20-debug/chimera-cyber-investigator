#!/usr/bin/env bash
# One-shot local run: install deps, generate samples, run tests, start the dashboard.
set -e
cd "$(dirname "$0")"
pip install -r requirements.txt
python -m forensic.sample_data
python -m pytest -q
streamlit run app.py
