# Persistent Project Structure

Each model type now follows the same persistent folder layout:

```text
<TYPE>\
  data\
    raw\          Original dataset files
    processed\    Processed feature/event exports when available
  models\         Trained model and scaler artifacts
  results\        Offline evaluation CSVs, metrics, benchmarks, and figures
    figures\      Training/evaluation/inference visual outputs
  live_logs\      Files tailed by the live listener
  live_scores\    JSONL model scores produced by the live listener
  src\            Type-specific preprocessing, training, and evaluation code
```

Current type folders:

```text
Firewall\
WEB LOGS MODEL\
SSH\
```

Neutral offline evaluation CSV names:

```text
Firewall\results\firewall_evaluation.csv
WEB LOGS MODEL\results\web_evaluation.csv
SSH\results\ssh_evaluation.csv
```

Live scoring remains coordinated from:

```text
live\generate_logs.py
live\listen_and_score.py
```

ELK/Docker live monitoring is coordinated from:

```text
elk\docker-compose.yml
elk\logstash\pipeline\cyber-live.conf
elk\setup_elk.py
elk\start_elk.ps1
elk\setup_kibana.ps1
```
