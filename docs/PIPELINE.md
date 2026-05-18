# Detailed Pipeline Documentation

## System Overview

The project implements three anomaly-detection pipelines:

```text
Firewall CSV rows
Apache/NASA HTTP access logs
SSH auth/Kippo honeypot logs
```

All three pipelines produce:

```text
trained model artifacts -> offline evaluation reports/figures -> live JSONL prediction streams -> Kibana dashboard panels
```

The offline machine-learning model type is the same for all three tasks:

```text
sklearn.ensemble.IsolationForest
```

Isolation Forest is used because the available data is either unlabeled or only partially labeled. The model learns a baseline distribution and gives higher anomaly scores to unusual points or windows.

## Data Sources

| Type | Source location | Collection method | Label quality |
| --- | --- | --- | --- |
| Firewall | `Firewall/data/raw/firewall.csv` | CSV stored in the repository | `Action` gives usable ground truth |
| Web | `WEB LOGS MODEL/data/raw/NASA_access_log_Jul95.gz` | NASA HTTP access log archive, downloaded by the script if missing | No security labels; pseudo labels for evaluation |
| SSH | `SSH/data/raw/dataset1_log_files.tgz` | SimpleWeb / University of Twente SSH Dataset 1 archive | No direct labels; behavior-rule pseudo labels |

## Persistent Folder Architecture

Each model type uses the same structure:

```text
<TYPE>/
  data/
    raw/          Original dataset files
    processed/    Parsed events or feature tables
  models/         Trained model and scaler artifacts
  results/        Evaluation CSV, metrics JSON, benchmarks, figures
    figures/      Confusion matrix, ROC, PR, score distribution, etc.
  live_logs/      Live raw log file tailed by the listener and Logstash
  live_scores/    Live model score JSONL output
  src/            Type-specific preprocessing, training, evaluation code
```

## Firewall Pipeline

### Input

Raw file:

```text
Firewall/data/raw/firewall.csv
```

Important columns:

```text
Source Port
Destination Port
NAT Source Port
NAT Destination Port
Action
Bytes
Bytes Sent
Bytes Received
Packets
Elapsed Time (sec)
pkts_sent
pkts_received
```

`Action == allow` is treated as normal baseline traffic. Other actions are treated as anomalies during evaluation.

### Processing And Feature Engineering

Code:

```text
Firewall/src/firewall_features.py
Firewall/src/preprocess_firewall.py
```

Main functions:

```text
load_firewall_data(path)
add_firewall_features(df)
```

Feature list:

```text
Source Port
Destination Port
Bytes
Packets
Elapsed Time (sec)
Bytes_per_Packet
Packet_Rate
Byte_Rate
Port_Diversity_Ratio
```

Derived features:

```text
Bytes_per_Packet = Bytes / (Packets + 1)
Packet_Rate = Packets / (Elapsed Time + 0.001)
Byte_Rate = Bytes / (Elapsed Time + 0.001)
Port_Diversity_Ratio = Destination Port / (Source Port + 1)
```

### Training

Code:

```text
Firewall/src/preprocess_firewall.py
Firewall/src/train_firewall.py
```

Training steps:

1. Load firewall CSV.
2. Add derived numeric features.
3. Select only `Action == allow` rows as normal baseline.
4. Fit `StandardScaler`.
5. Split scaled normal rows into train and held-out normal rows.
6. Train `IsolationForest(n_estimators=100, contamination=0.35, random_state=42)`.
7. Save artifacts:

```text
Firewall/models/firewall_scaler.pkl
Firewall/models/firewall_isolation.pkl
Firewall/models/firewall_scaler_test.pkl
```

### Offline Scoring And Evaluation

Code:

```text
Firewall/src/evaluate_firewall.py
evaluation/evaluate_all_models.py
```

Evaluation set:

```text
held-out normal baseline rows + non-allow rows
```

Outputs:

```text
Firewall/results/firewall_evaluation.csv
Firewall/results/firewall_metrics.json
Firewall/results/performance_summary.json
Firewall/results/inference_benchmark.csv
Firewall/results/feature_score_correlations.csv
Firewall/results/figures/*.png
```

## Web Pipeline

### Input

Raw archive:

```text
WEB LOGS MODEL/data/raw/NASA_access_log_Jul95.gz
```

The Web script downloads the NASA HTTP archive if it is missing.

Main script:

```text
WEB LOGS MODEL/src/nasa_anomaly_detection.py
```

### Processing

Main functions:

```text
ensure_dataset()
parse_logs(filepath)
engineer_features(df)
```

Parsed fields:

```text
host
time
method
url
status
bytes
hour
```

The raw access log is aggregated by:

```text
(host, hour)
```

This means the Web model does not score isolated single log lines offline. It scores per-host hourly behavior windows.

### Feature Engineering

Feature list:

```text
request_count
unique_urls
avg_bytes
total_bytes
error_rate
status_404
status_500
post_rate
url_diversity
bytes_per_req
error_to_ok_ratio
max_bytes
large_req_count
```

The model sees a numeric summary of a host's behavior within one hour. For example, a host that suddenly requests many unique URLs, returns many `404`/`500` responses, posts more often than usual, or transfers unusually large bytes can receive a higher anomaly score.

### Training

Code:

```text
WEB LOGS MODEL/src/nasa_anomaly_detection.py
```

Training steps:

1. Ensure the NASA dataset exists.
2. Parse Apache-style access lines.
3. Aggregate by host/hour.
4. Scale feature columns with `StandardScaler`.
5. Train `IsolationForest(n_estimators=200, contamination=0.05, random_state=42)`.
6. Save artifacts:

```text
WEB LOGS MODEL/models/anomaly_model.pkl
WEB LOGS MODEL/models/scaler.pkl
```

### Evaluation

The NASA log does not provide attack labels. The evaluation script uses a pseudo-label:

```text
anomaly if error_rate > 0.5
```

This creates a very imbalanced validation set. The Web ROC-AUC is high, but PR-AUC is low because pseudo anomalies are rare.

Outputs:

```text
WEB LOGS MODEL/results/web_evaluation.csv
WEB LOGS MODEL/results/flagged_anomalies.csv
WEB LOGS MODEL/results/web_metrics.json
WEB LOGS MODEL/results/performance_summary.json
WEB LOGS MODEL/results/inference_benchmark.csv
WEB LOGS MODEL/results/feature_score_correlations.csv
WEB LOGS MODEL/results/figures/*.png
```

## SSH Pipeline

### Input

Raw archive:

```text
SSH/data/raw/dataset1_log_files.tgz
```

Source:

```text
SimpleWeb / University of Twente SSH Dataset 1
```

The archive contains anonymized SSH authentication logs and Kippo honeypot logs.

### Processing

Code:

```text
SSH/src/preprocess_ssh.py
SSH/src/ssh_features.py
```

Main functions:

```text
ensure_raw_dataset()
parse_ssh_logs(raw_root)
parse_auth_line(line)
parse_auth_file(path)
parse_kippo_file(path)
build_feature_table(events)
```

Parsed event types:

```text
failed_login
failed_login_invalid
invalid_user
accepted_login
auth_failure
connection
connection_scan
connection_closed
command
```

The raw SSH events are aggregated by:

```text
(source_ip, 10-minute window)
```

### Feature Engineering

Feature list:

```text
connection_count
failed_login_count
auth_failure_count
invalid_user_count
accepted_login_count
command_count
suspicious_command_count
unique_users
unique_passwords
source_port_count
failure_rate
invalid_user_rate
commands_per_accepted
success_after_fail
burst_score
```

Pseudo-label rules mark a window as suspicious when it shows behavior such as:

```text
brute force
user enumeration
connection bursts
post-login command activity
suspicious commands
honeypot sessions
```

### Training

Code:

```text
SSH/src/preprocess_ssh.py
SSH/src/train_ssh.py
```

Training steps:

1. Extract the dataset archive if needed.
2. Parse auth and Kippo logs into normalized event records.
3. Aggregate events into per-source-IP 10-minute windows.
4. Select low-activity windows as the normal baseline.
5. Fit `StandardScaler`.
6. Train `IsolationForest(n_estimators=200, contamination=0.12, random_state=42)`.
7. Save artifacts:

```text
SSH/models/ssh_isolation.pkl
SSH/models/ssh_scaler.pkl
```

### Evaluation

Evaluation uses held-out normal windows and pseudo-anomaly windows from the rule-based labels.

Outputs:

```text
SSH/results/ssh_evaluation.csv
SSH/results/ssh_metrics.json
SSH/results/performance_summary.json
SSH/results/inference_benchmark.csv
SSH/results/feature_score_correlations.csv
SSH/results/figures/*.png
```

## Live Scoring Pipeline

Files:

```text
live/generate_logs.py
live/listen_and_score.py
```

### Generator

`live/generate_logs.py` writes synthetic examples to:

```text
Firewall/live_logs/firewall_live.csv
WEB LOGS MODEL/live_logs/web_access.log
SSH/live_logs/ssh_auth.log
```

It generates a mix of normal-looking and suspicious-looking events.

The generator deliberately varies:

```text
Web: source IP, method, URL path, status code, byte count
SSH: source IP, user, sensor, auth method, failed login style, scan style
Firewall: action, ports, packet counts, byte counts, elapsed time
```

Useful options:

```text
--attack-rate  Approximate suspicious event ratio per log type
--seed         Repeatable random seed for demos
```

### Listener And Scorer

`live/listen_and_score.py` tails all three files and loads each trained model.

Firewall live scoring:

```text
one firewall CSV row -> feature vector -> scaler -> Isolation Forest -> score JSONL row
```

Web live scoring:

```text
one access line -> update host/hour window -> aggregate current window -> scaler -> Isolation Forest -> score JSONL row
```

SSH live scoring:

```text
one auth line -> update source_ip/10-minute window -> aggregate current window -> scaler -> Isolation Forest -> score JSONL row
```

Live score files:

```text
Firewall/live_scores/firewall_scores.jsonl
WEB LOGS MODEL/live_scores/web_scores.jsonl
SSH/live_scores/ssh_scores.jsonl
```

Each score payload includes:

```text
model
scored_at
prediction
is_anomaly
anomaly_score
risk_score
```

Web and SSH also include a normalized `status_label` field for dashboard grouping.

## Model Scoring Semantics

Isolation Forest returns:

```text
prediction = 1   normal
prediction = -1  anomaly
```

The repository stores:

```text
anomaly_score = -model.decision_function(...)
risk_score = sigmoid(anomaly_score)
```

Higher `anomaly_score` and `risk_score` mean the event/window is more unusual.

For window-based models, one new log line can still produce one new score. The score is not for the single line alone. It is for the current state of that line's window after the new line is added.

Example for Web:

```text
line 1 for host A at hour 10 -> window_events = 1 -> score host A/hour 10
line 2 for host A at hour 10 -> window_events = 2 -> score updated host A/hour 10
line 3 for host B at hour 10 -> window_events = 1 -> score host B/hour 10
```

## Evaluation And Explanation

The shared evaluator is:

```text
evaluation/evaluate_all_models.py
```

It generates:

```text
confusion_matrix.png
roc_curve.png
precision_recall_curve.png
score_distribution.png
label_balance.png
feature_score_correlation.png
inference_latency.png
```

The explanation approach is feature/score correlation:

```text
feature_score_correlations.csv
feature_score_correlation.png
```

This is not a full causal explanation method. It is a practical interpretability view that shows which engineered features move most strongly with the model's anomaly score.

## ELK Pipeline

Docker Compose file:

```text
elk/docker-compose.yml
```

Logstash pipeline:

```text
elk/logstash/pipeline/cyber-live.conf
```

Kibana setup:

```text
elk/setup_elk.py
elk/setup_kibana.sh
```

Flow:

```text
local live_logs + live_scores
  -> Docker bind mount
  -> Logstash file inputs
  -> parsing and normalization
  -> Elasticsearch indices
  -> Kibana data views, Vega visualizations, dashboard
```
