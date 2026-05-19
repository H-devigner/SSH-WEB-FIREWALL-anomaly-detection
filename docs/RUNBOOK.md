# Windows Clone-And-Run Terminal Runbook

This file is written for someone using **Windows PowerShell**. The repository is intentionally documented for Windows only.

## 1. Clone And Install Dependencies

Open PowerShell:

```powershell
git clone https://github.com/H-devigner/SSH-WEB-FIREWALL-anomaly-detection.git
cd SSH-WEB-FIREWALL-anomaly-detection
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks local scripts:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Required external software:

```text
Docker Desktop for Windows
Docker Compose v2, available as docker compose
```

Check Docker:

```powershell
docker --version
docker compose version
```

## 2. Train And Evaluate The Models

Run from the repository root with the virtual environment activated.

### Firewall

```powershell
python .\Firewall\src\preprocess_firewall.py
python .\Firewall\src\train_firewall.py
python .\Firewall\src\evaluate_firewall.py
```

Outputs:

```text
Firewall\models\firewall_scaler.pkl
Firewall\models\firewall_isolation.pkl
Firewall\models\firewall_scaler_test.pkl
Firewall\results\firewall_evaluation.csv
Firewall\results\firewall_metrics.json
```

### Web

```powershell
python "WEB LOGS MODEL\src\nasa_anomaly_detection.py"
```

Outputs:

```text
WEB LOGS MODEL\models\anomaly_model.pkl
WEB LOGS MODEL\models\scaler.pkl
WEB LOGS MODEL\results\web_evaluation.csv
WEB LOGS MODEL\results\web_metrics.json
```

### SSH

```powershell
python .\SSH\src\preprocess_ssh.py
python .\SSH\src\train_ssh.py
python .\SSH\src\evaluate_ssh.py
```

Outputs:

```text
SSH\data\processed\ssh_events_sample.csv
SSH\data\processed\ssh_features.csv
SSH\models\ssh_isolation.pkl
SSH\models\ssh_scaler.pkl
SSH\results\ssh_evaluation.csv
SSH\results\ssh_metrics.json
```

### Shared Evaluation And Figures

```powershell
python .\evaluation\evaluate_all_models.py
```

Outputs:

```text
evaluation\performance_summary.csv
evaluation\performance_summary.json
Firewall\results\figures\*.png
WEB LOGS MODEL\results\figures\*.png
SSH\results\figures\*.png
```

## 3. Start Docker ELK

PowerShell terminal 1:

```powershell
.\.venv\Scripts\Activate.ps1
Copy-Item .\elk\.env.example .\elk\.env
.\elk\start_elk.ps1
```

Wait until Kibana is reachable:

```text
http://localhost:5601
```

Then install Elasticsearch templates, Kibana data views, visualizations, and the dashboard:

```powershell
.\elk\setup_kibana.ps1
```

Open:

```text
http://localhost:5601/app/dashboards#/view/cyber-live-security-dashboard
```

## 4. Run Live Scoring In Multiple PowerShell Terminals

Use three PowerShell terminals from the repository root.

### Terminal 1: ELK

Keep Elasticsearch, Kibana, and Logstash running:

```powershell
.\.venv\Scripts\Activate.ps1
.\elk\start_elk.ps1
.\elk\setup_kibana.ps1
```

### Terminal 2: Model Listener

This tails the log files and writes prediction JSONL files:

```powershell
.\.venv\Scripts\Activate.ps1
python .\live\listen_and_score.py
```

Optional one-shot test mode:

```powershell
python .\live\listen_and_score.py --from-start --max-events 30
```

### Terminal 3: Log Generator

This writes synthetic logs for all three types:

```powershell
.\.venv\Scripts\Activate.ps1
python .\live\generate_logs.py --reset --count 100 --interval 0.5 --attack-rate 0.3
```

Useful shorter smoke test:

```powershell
python .\live\generate_logs.py --reset --count 10 --interval 0 --attack-rate 0.35 --seed 42
```

## 5. Watch Local Files

Optional PowerShell terminals:

```powershell
Get-Content -Wait .\Firewall\live_scores\firewall_scores.jsonl
```

```powershell
Get-Content -Wait "WEB LOGS MODEL\live_scores\web_scores.jsonl"
```

```powershell
Get-Content -Wait .\SSH\live_scores\ssh_scores.jsonl
```

## 6. Stop Or Reset ELK

Stop containers:

```powershell
.\elk\stop_elk.ps1
```

Stop containers and remove Elasticsearch/Logstash volumes:

```powershell
.\elk\stop_elk.ps1 -Reset
```

After reset:

```powershell
.\elk\start_elk.ps1
.\elk\setup_kibana.ps1
```

## 7. Rebuild The Academic Presentation

```powershell
.\.venv\Scripts\Activate.ps1
python .\docs\create_presentation.py
```

Output:

```text
docs\SSH_WEB_FIREWALL_Academic_Presentation.pptx
```

## 8. Common Problems

### PowerShell Blocks Scripts

Run this only for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

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

```powershell
python .\live\generate_logs.py --count 50 --interval 0.2
```

For a more aggressive dashboard demo:

```powershell
python .\live\generate_logs.py --count 100 --interval 0.2 --attack-rate 0.45
```

### Logstash Does Not Pick Up New Parser Changes

Rerun:

```powershell
.\elk\setup_kibana.ps1
```

The script restarts the Logstash container.

### Docker Container Name Conflict

Stop this project's containers:

```powershell
.\elk\stop_elk.ps1
```

If stopped containers still exist:

```powershell
docker ps -a
docker rm ssh-web-firewall-elasticsearch ssh-web-firewall-kibana ssh-web-firewall-logstash
```
