LIVE FILE SCORING ON WINDOWS
----------------------------
This folder contains a local file-based live demo for Windows PowerShell:

1. generate_logs.py writes synthetic Firewall, Web, and SSH logs.
2. listen_and_score.py tails those files, aggregates features where needed,
   scores each event/window with the matching trained model, and writes JSONL
   score outputs.

No Logstash or API server is required for local scoring. ELK is only needed for
Kibana dashboards.

Default log files:
- Firewall\live_logs\firewall_live.csv
- WEB LOGS MODEL\live_logs\web_access.log
- SSH\live_logs\ssh_auth.log

Default score files:
- Firewall\live_scores\firewall_scores.jsonl
- WEB LOGS MODEL\live_scores\web_scores.jsonl
- SSH\live_scores\ssh_scores.jsonl

Web and SSH score outputs include `status_label` for readable dashboard
grouping. Web labels are `success`, `redirect`, `client_error`,
`server_error`, or `other`; SSH labels include `accepted`, `failed`,
`invalid_user`, `auth_failure`, `connection`, `command`, and `other`.

Example, two PowerShell terminals from the repository root:

Terminal 1:
```powershell
.\.venv\Scripts\Activate.ps1
python .\live\listen_and_score.py --from-start
```

Terminal 2:
```powershell
.\.venv\Scripts\Activate.ps1
python .\live\generate_logs.py --reset --count 30 --interval 0.5 --attack-rate 0.3
```

One-shot test:
```powershell
.\.venv\Scripts\Activate.ps1
python .\live\generate_logs.py --reset --count 10 --interval 0 --attack-rate 0.35 --seed 42
python .\live\listen_and_score.py --from-start --max-events 30
```

Generator options:
- `--attack-rate` controls the approximate suspicious ratio for each type.
- `--seed` makes the generated demo repeatable.
- Web logs vary client IPs, methods, URLs, byte counts, and HTTP outcomes.
- SSH logs vary source IPs, users, sensors, auth methods, failed logins,
  invalid users, authentication failures, scans, and closed connections.

ELK integration:
See ..\elk\README.md for Docker Compose, Logstash file ingestion,
Elasticsearch indices, and the Kibana live security dashboard.
