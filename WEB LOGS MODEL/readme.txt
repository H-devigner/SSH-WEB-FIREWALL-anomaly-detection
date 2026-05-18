WEB ANOMALY MODEL
-----------------
Offline Isolation Forest pipeline for NASA HTTP access logs.

Architecture:
data/raw/                  Original NASA HTTP log archive
data/processed/            Reserved for processed feature exports
models/                    Isolation Forest model and scaler
results/                   Evaluation CSV, flagged windows, metrics, and figures
live_logs/                 Local live Apache-style access log file
live_scores/               Local live Web JSONL score output
src/nasa_anomaly_detection.py  Download/parse, feature engineering, train, score
src/test.py                Small manual scoring smoke test
src/test_model.py          Web-specific offline sanity checks

Execution:
python src/nasa_anomaly_detection.py
python src/test_model.py

Notes:
The model scores per-host hourly behavior windows. Evaluation labels are
pseudo labels based on HTTP error-heavy windows, not a fully labeled security
ground-truth dataset.
