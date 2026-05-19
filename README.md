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

The live generator supports `--attack-rate` and `--seed`, and it varies Web source IPs, URLs, HTTP methods/statuses, SSH source IPs, users, sensors, accepted logins, invalid users, authentication failures, scans, and closed connections.

## Stop ELK

```powershell
.\elk\stop_elk.ps1
```

Remove ELK volumes and reset the demo state:

```powershell
.\elk\stop_elk.ps1 -Reset
```
