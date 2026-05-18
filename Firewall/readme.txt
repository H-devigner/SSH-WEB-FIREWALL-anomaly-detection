FIREWALL ANOMALY MODEL
----------------------
Offline Isolation Forest pipeline for firewall CSV data.

Architecture:
data/raw/           Source firewall.csv dataset
data/processed/     Reserved for processed feature exports
models/             Trained model and scaler artifacts
results/            Evaluation CSV, metrics, and figures
live_logs/          Local live firewall log file
live_scores/        Local live firewall JSONL score output
src/                Preprocess, train, evaluate, and feature helpers

Execution:
python src/preprocess_firewall.py
python src/train_firewall.py
python src/evaluate_firewall.py

Notes:
The model trains on Action == "allow" rows as the normal baseline.
Evaluation combines held-out normal baseline rows with non-allow rows
treated as anomaly labels.
