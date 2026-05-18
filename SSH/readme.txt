SSH ANOMALY MODEL
-----------------
Public dataset:
SimpleWeb / University of Twente SSH Dataset 1 log archive.
Downloaded archive: data/raw/dataset1_log_files.tgz

Architecture:
data/raw/                  Original SSH auth/Kippo logs
data/processed/            Event sample and engineered feature windows
models/                    Isolation Forest model and scaler
results/                   Evaluation CSV, metrics, and figures
live_logs/                 Local live SSH auth log file
live_scores/               Local live SSH JSONL score output
src/preprocess_ssh.py      Parse raw logs and build feature table
src/train_ssh.py           Train Isolation Forest on low-activity baseline
src/evaluate_ssh.py        Evaluate against pseudo attack labels

Execution:
python src/preprocess_ssh.py
python src/train_ssh.py
python src/evaluate_ssh.py

Notes:
The public SSH dataset is unlabeled honeypot/auth data. Evaluation labels are
pseudo labels based on brute force, user enumeration, connection bursts, and
post-login command activity. Treat the metrics as a sanity check, not a
production accuracy guarantee.

The repository keeps the compressed dataset archive, not the full extracted
raw tree. preprocess_ssh.py extracts data/raw/dataset1_log_files.tgz on demand.
