# Clone-And-Run Terminal Runbook

This file is written for someone who clones the repository from GitHub and wants to reproduce the full system.

## 1. Clone And Install Dependencies

Terminal:

```bash
git clone https://github.com/Marouansw/SSH-WEB-FIREWALL.git
cd SSH-WEB-FIREWALL
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Required external software:

```text
Docker Desktop or Docker Engine
Docker Compose v2, available as docker compose
```

Check Docker:

```bash
docker --version
docker compose version
```

## 2. Train And Evaluate The Models

Run from the repository root with the virtual environment activated.

### Firewall

```bash
python Firewall/src/preprocess_firewall.py
python Firewall/src/train_firewall.py
python Firewall/src/evaluate_firewall.py
```

Outputs:

```text
Firewall/models/firewall_scaler.pkl
Firewall/models/firewall_isolation.pkl
Firewall/models/firewall_scaler_test.pkl
Firewall/results/firewall_evaluation.csv
Firewall/results/firewall_metrics.json
```

### Web

```bash
python "WEB LOGS MODEL/src/nasa_anomaly_detection.py"
```

Outputs:

```text
WEB LOGS MODEL/models/anomaly_model.pkl
WEB LOGS MODEL/models/scaler.pkl
WEB LOGS MODEL/results/web_evaluation.csv
WEB LOGS MODEL/results/web_metrics.json
```

### SSH

```bash
python SSH/src/preprocess_ssh.py
python SSH/src/train_ssh.py
python SSH/src/evaluate_ssh.py
```

Outputs:

```text
SSH/data/processed/ssh_events_sample.csv
SSH/data/processed/ssh_features.csv
SSH/models/ssh_isolation.pkl
SSH/models/ssh_scaler.pkl
SSH/results/ssh_evaluation.csv
SSH/results/ssh_metrics.json
```

### Shared Evaluation And Figures

```bash
python evaluation/evaluate_all_models.py
```

Outputs:

```text
evaluation/performance_summary.csv
evaluation/performance_summary.json
Firewall/results/figures/*.png
WEB LOGS MODEL/results/figures/*.png
SSH/results/figures/*.png
```

## 3. Start Docker ELK

Terminal 1:

```bash
source .venv/bin/activate
cp elk/.env.example elk/.env
elk/start_elk.sh
```

Wait until Kibana is reachable:

```text
http://localhost:5601
```

Then install Elasticsearch templates, Kibana data views, visualizations, and the dashboard:

```bash
elk/setup_kibana.sh
```

Open:

```text
http://localhost:5601/app/dashboards#/view/cyber-live-security-dashboard
```

## 4. Run Live Scoring In Multiple Terminals

Use three terminals from the repository root.

### Terminal 1: ELK

Keep Elasticsearch, Kibana, and Logstash running:

```bash
source .venv/bin/activate
elk/start_elk.sh
elk/setup_kibana.sh
```

### Terminal 2: Model Listener

This tails the log files and writes prediction JSONL files:

```bash
source .venv/bin/activate
python live/listen_and_score.py
```

Optional one-shot test mode:

```bash
python live/listen_and_score.py --from-start --max-events 30
```

### Terminal 3: Log Generator

This writes synthetic logs for all three types:

```bash
source .venv/bin/activate
python live/generate_logs.py --reset --count 100 --interval 0.5
```

Useful shorter smoke test:

```bash
python live/generate_logs.py --reset --count 10 --interval 0
```

## 5. Watch Local Files

Optional terminals:

```bash
tail -f Firewall/live_scores/firewall_scores.jsonl
```

```bash
tail -f "WEB LOGS MODEL/live_scores/web_scores.jsonl"
```

```bash
tail -f SSH/live_scores/ssh_scores.jsonl
```

## 6. Stop Or Reset ELK

Stop containers:

```bash
elk/stop_elk.sh
```

Stop containers and remove Elasticsearch/Logstash volumes:

```bash
elk/stop_elk.sh --reset
```

After reset:

```bash
elk/start_elk.sh
elk/setup_kibana.sh
```

## 7. Rebuild The Academic Presentation

```bash
source .venv/bin/activate
python docs/create_presentation.py
```

Output:

```text
docs/SSH_WEB_FIREWALL_Academic_Presentation.pptx
```

## 8. Common Problems

### Kibana Dashboard Is Empty

Use the Kibana time picker and select:

```text
Last 15 minutes
```

or a wider range such as:

```text
Last 24 hours
```

Then generate new logs:

```bash
python live/generate_logs.py --count 50 --interval 0.2
```

### Logstash Does Not Pick Up New Parser Changes

Rerun:

```bash
elk/setup_kibana.sh
```

The script restarts the Logstash container.

### Docker Container Name Conflict

Stop this project's containers:

```bash
elk/stop_elk.sh
```

If stopped containers still exist:

```bash
docker ps -a
docker rm ssh-web-firewall-elasticsearch ssh-web-firewall-kibana ssh-web-firewall-logstash
```
