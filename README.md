# SSH/Web/Firewall Anomaly Detection

This repository contains three Isolation Forest anomaly-detection pipelines and a live Docker-based ELK dashboard.

This project is documented and scripted for **Windows PowerShell only**.

- Firewall traffic model
- Web access log model
- SSH authentication/honeypot log model

Each model has the same high-level architecture:

```text
data collection -> parsing/preprocessing -> feature engineering -> training -> evaluation -> live scoring -> Kibana monitoring
```

## Quick Start

Windows prerequisites:

- Windows 10/11
- PowerShell 5.1 or newer
- Python 3.11 or newer
- Docker Desktop with Docker Compose v2
- Git for Windows

Clone and install Python dependencies:

```powershell
git clone https://github.com/H-devigner/SSH-WEB-FIREWALL-anomaly-detection.git
cd SSH-WEB-FIREWALL-anomaly-detection
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run all offline preprocessing, training, and evaluation:

```powershell
python .\Firewall\src\preprocess_firewall.py
python .\Firewall\src\train_firewall.py
python .\Firewall\src\evaluate_firewall.py

python "WEB LOGS MODEL\src\nasa_anomaly_detection.py"

python .\SSH\src\preprocess_ssh.py
python .\SSH\src\train_ssh.py
python .\SSH\src\evaluate_ssh.py

python .\evaluation\evaluate_all_models.py
```

Start Elasticsearch and Kibana:

```powershell
.\elk\start_elk.ps1
.\elk\setup_kibana.ps1
```

The ELK scripts create `elk\.env` if it is missing and backfill any new required settings from `elk\.env.example`.

Open Kibana:

```text
http://localhost:5601
```

Dashboard:

```text
SSH/Web/Firewall Live Security Dashboard
```

Run the live demo in two more terminals:

PowerShell terminal 1:

```powershell
.\.venv\Scripts\Activate.ps1
python .\live\listen_and_score.py
```

PowerShell terminal 2:

```powershell
.\.venv\Scripts\Activate.ps1
python .\live\generate_logs.py --reset --count 100 --interval 0.5 --attack-rate 0.3
```

## Main Documentation

- [Detailed pipeline documentation](docs/PIPELINE.md)
- [Clone-and-run terminal runbook](docs/RUNBOOK.md)
- [Kibana guide](docs/KIBANA_GUIDE.md)
- [Sigma rule engine guide](docs/SIGMA_RULES.md)
- [Evaluation results](docs/RESULTS.md)
- [Academic presentation outline](docs/PRESENTATION.md)
- [PowerPoint deck](docs/SSH_WEB_FIREWALL_Academic_Presentation.pptx)

## Repository Layout

```text
Firewall\              Firewall data, model, evaluation, live files
WEB LOGS MODEL\        Web/NASA HTTP data, model, evaluation, live files
SSH\                   SSH data, model, evaluation, live files
evaluation\            Shared multi-model evaluator
live\                  Log generator and live file listener/scorer
elk\                   Docker Compose ELK stack and Kibana setup
docs\                  Detailed documentation and presentation assets
```

## Model Summary

All three models use `sklearn.ensemble.IsolationForest`.

| Type | Input unit | Training baseline | Evaluation labels |
| --- | --- | --- | --- |
| Firewall | One firewall CSV row | `Action == allow` rows | Ground truth from `Action` |
| Web | Per-host hourly access window | NASA HTTP behavior windows | Pseudo labels from high HTTP error rate |
| SSH | Per-source-IP 10-minute window | Low-activity SSH windows | Pseudo labels from SSH behavior rules |

## End-To-End Data Flow

The project has two connected flows: an offline flow that creates model artifacts, and a live flow that tails logs, scores them, enriches them with Sigma-style rule matches, and visualizes everything in Kibana.

### Offline Training And Evaluation Flow

| Phase | Code | Input | Output |
| --- | --- | --- | --- |
| Data collection | `Firewall\data\raw\firewall.csv`, `WEB LOGS MODEL\src\nasa_anomaly_detection.py`, `SSH\src\preprocess_ssh.py` | Public/sample raw firewall, NASA HTTP, and SSH/honeypot logs | Raw local datasets under each model folder |
| Parsing and cleaning | `Firewall\src\preprocess_firewall.py`, `WEB LOGS MODEL\src\nasa_anomaly_detection.py`, `SSH\src\preprocess_ssh.py` | Raw CSV/log lines | Clean rows with timestamps, numeric fields, actions/statuses, IPs, URLs, usernames, and event types |
| Feature engineering | `Firewall\src\firewall_features.py`, `engineer_features()` in `WEB LOGS MODEL\src\nasa_anomaly_detection.py`, `SSH\src\ssh_features.py` | Clean rows/events | Numeric feature tables ready for `StandardScaler` |
| Training | `Firewall\src\train_firewall.py`, `train_model()` in `WEB LOGS MODEL\src\nasa_anomaly_detection.py`, `SSH\src\train_ssh.py` | Numeric feature tables | Isolation Forest model files and scaler files under each `models\` folder |
| Evaluation | `Firewall\src\evaluate_firewall.py`, `WEB LOGS MODEL\src\nasa_anomaly_detection.py`, `SSH\src\evaluate_ssh.py`, `evaluation\evaluate_all_models.py` | Saved models, scalers, validation/test features | Metrics JSON/CSV files and figures under `results\` and `evaluation\` |

### Live Monitoring Flow

| Phase | Code | Input | Output |
| --- | --- | --- | --- |
| Generate demo logs | `live\generate_logs.py` | `--count`, `--interval`, `--attack-rate`, optional `--seed` | Appended raw logs in `Firewall\live_logs\firewall_live.csv`, `WEB LOGS MODEL\live_logs\web_access.log`, and `SSH\live_logs\ssh_auth.log` |
| Tail and parse new lines | `live\listen_and_score.py` | New raw lines from the three live log files | Parsed event dictionaries |
| Convert to model input | `add_firewall_features()`, `web_features()`, `build_feature_table()` | Parsed events or updated Web/SSH windows | Final numeric feature row passed to the scaler/model |
| Score with model | `score_frame()` in `live\listen_and_score.py` | Scaled feature row | `prediction`, `is_anomaly`, `anomaly_score`, and normalized `risk_score` |
| Rule enrichment | `live\sigma_rule_engine.py` and `sigma\rules\*.yml` | The scored event dictionary | Extra `sigma_*` fields such as `sigma_match`, `sigma_rule_id`, and `sigma_rule_level` |
| Write prediction stream | `append_score()` in `live\listen_and_score.py` | Scored/enriched event | JSONL files in each `live_scores\` folder |
| Ingest into Elasticsearch | `elk\logstash\pipeline\cyber-live.conf` | Raw log files and JSONL score files mounted into Docker | `cyber-live-raw-*` and `cyber-live-scores-*` Elasticsearch indices |
| Visualize | `elk\setup_elk.py` | Elasticsearch indices | Kibana data views, 14 dashboard panels, and live auto-refresh |

Web and SSH are window-based models, but the listener still writes one score for every consumed log line. Each new line updates the current host/hour Web window or source-IP/10-minute SSH window, then the updated window is scored immediately.

### Firewall Example Scenario

Example raw input written to `Firewall\live_logs\firewall_live.csv`:

```csv
Source Port,Destination Port,NAT Source Port,NAT Destination Port,Action,Bytes,Bytes Sent,Bytes Received,Packets,Elapsed Time (sec),pkts_sent,pkts_received
51514,443,0,0,deny,85120,43000,42120,88,2.5,44,44
```

| Phase | Input | Output |
| --- | --- | --- |
| Parse | One CSV row | `{action: "deny", source_port: 51514, destination_port: 443, bytes: 85120, packets: 88}` |
| Feature engineering | Parsed row | `Source Port`, `Destination Port`, `Bytes`, `Packets`, `Elapsed Time (sec)`, `Bytes_per_Packet`, `Packet_Rate`, `Byte_Rate`, `Port_Diversity_Ratio` |
| Scoring | One scaled firewall feature row | JSONL prediction such as `{model: "firewall", action: "deny", destination_port: 443, is_anomaly: true, risk_score: 0.73}` |
| Elasticsearch/Kibana | Raw CSV row and JSONL prediction | Raw firewall index, firewall score index, action panels, destination-port panels, anomaly/risk panels |

### Web Example Scenario

Example raw input written to `WEB LOGS MODEL\live_logs\web_access.log`:

```text
203.0.113.77 - - [19/May/2026:14:05:20 +0000] "POST /wp-login.php HTTP/1.1" 401 185000
```

| Phase | Input | Output |
| --- | --- | --- |
| Parse | One Apache access log line | `{client_ip: "203.0.113.77", http_method: "POST", url_path: "/wp-login.php", http_status: 401, status_label: "client_error"}` |
| Window update | Parsed event | The event is added to the `203.0.113.77` + current-hour window |
| Feature engineering | All events currently in that host/hour window | `request_count`, `unique_urls`, `avg_bytes`, `total_bytes`, `error_rate`, `status_404`, `status_500`, `post_rate`, `url_diversity`, `bytes_per_req`, `error_to_ok_ratio`, `max_bytes`, `large_req_count` |
| Scoring | One scaled Web window feature row | JSONL prediction such as `{model: "web", client_ip: "203.0.113.77", url_path: "/wp-login.php", window_events: 7, is_anomaly: true, risk_score: 0.68}` |
| Elasticsearch/Kibana | Raw Apache line and JSONL prediction | Raw Web index, Web score index, status panels, error-URL panels, anomaly/risk panels |

### SSH Example Scenario

Example raw input written to `SSH\live_logs\ssh_auth.log`:

```text
May 19 14:05:20 ssh-sensor-01 sshd[30214]: Failed password for invalid user root from 203.0.113.90 port 51222 ssh2
```

| Phase | Input | Output |
| --- | --- | --- |
| Parse | One SSH auth log line | `{ssh_sensor: "ssh-sensor-01", source_ip: "203.0.113.90", source_port: 51222, username: "root", event_type: "failed_login_invalid", status_label: "invalid_user"}` |
| Window update | Parsed event | The event is added to the `203.0.113.90` + current 10-minute window |
| Feature engineering | All events currently in that source-IP/10-minute window | `connection_count`, `failed_login_count`, `auth_failure_count`, `invalid_user_count`, `accepted_login_count`, `unique_users`, `source_port_count`, `failure_rate`, `invalid_user_rate`, `success_after_fail`, `burst_score`, and related SSH behavior features |
| Scoring | One scaled SSH window feature row | JSONL prediction such as `{model: "ssh", source_ip: "203.0.113.90", username: "root", window_events: 5, is_anomaly: true, risk_score: 0.81}` |
| Elasticsearch/Kibana | Raw SSH line and JSONL prediction | Raw SSH index, SSH score index, login-status panels, username panels, source-IP risk panels |

## Latest Offline Results

| Model | Rows | ROC-AUC | PR-AUC | Accuracy |
| --- | ---: | ---: | ---: | ---: |
| Firewall | 35,420 | 0.9686 | 0.9787 | 0.9244 |
| Web | 182,278 | 0.9855 | 0.1432 | 0.9551 |
| SSH | 2,569 | 0.9931 | 0.9946 | 0.9560 |

The Web PR-AUC is low because the pseudo anomaly class is extremely rare: 942 anomaly windows out of 182,278 total windows.

## Live Monitoring

The live listener tails three local files:

```text
Firewall\live_logs\firewall_live.csv
WEB LOGS MODEL\live_logs\web_access.log
SSH\live_logs\ssh_auth.log
```

It writes model score JSONL files:

```text
Firewall\live_scores\firewall_scores.jsonl
WEB LOGS MODEL\live_scores\web_scores.jsonl
SSH\live_scores\ssh_scores.jsonl
```

Logstash reads both the raw log files and the score files, indexes them into Elasticsearch, and Kibana visualizes raw activity, prediction volume, anomaly mix, risk, and normalized status fields.

The dashboard includes these panels:

```text
Prediction Trend by Model
Prediction Mix by Model
Average Risk by Model
Raw Log Volume by Type
Firewall Actions
Web Status Outcomes
SSH Login Status
Top SSH Source IP Risk
Firewall Destination Ports by Action
Web Error URLs by Status
SSH Usernames by Status
Risk Bands by Model
Sigma Rule Hits by Rule
Sigma Rule Hits by Severity
```

The live generator supports `--attack-rate` and `--seed`, and it varies Web source IPs, URLs, HTTP methods/statuses, SSH source IPs, users, sensors, accepted logins, invalid users, authentication failures, scans, and closed connections.

## Stop ELK

```powershell
.\elk\stop_elk.ps1
```

Remove ELK volumes and reset the demo state:

```powershell
.\elk\stop_elk.ps1 -Reset
```
