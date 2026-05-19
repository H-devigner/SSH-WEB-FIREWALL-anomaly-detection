# Kibana Guide

## Purpose

Kibana is used as the live monitoring layer for:

- Raw Firewall/Web/SSH logs
- Live model prediction JSONL files
- Model risk scores and anomaly decisions
- Operational status categories such as firewall action, web status outcome, and SSH login status

## Start Kibana On Windows

Use Windows PowerShell from the repository root.

```powershell
Copy-Item .\elk\.env.example .\elk\.env
.\elk\start_elk.ps1
.\elk\setup_kibana.ps1
```

Open:

```text
http://localhost:5601
```

Dashboard:

```text
SSH/Web/Firewall Live Security Dashboard
```

## Data Flow Into Kibana

```text
live\generate_logs.py
  -> Firewall\live_logs\firewall_live.csv
  -> WEB LOGS MODEL\live_logs\web_access.log
  -> SSH\live_logs\ssh_auth.log

live\listen_and_score.py
  -> Firewall\live_scores\firewall_scores.jsonl
  -> WEB LOGS MODEL\live_scores\web_scores.jsonl
  -> SSH\live_scores\ssh_scores.jsonl

Logstash
  -> cyber-live-raw-*
  -> cyber-live-scores-*

Kibana
  -> data views
  -> saved Vega visualizations
  -> dashboard
```

## Data Views

The setup script creates these Kibana data views:

```text
cyber-live-scores
cyber-live-raw
cyber-live-raw-firewall
cyber-live-raw-web
cyber-live-raw-ssh
```

All use `@timestamp` as the time field.

## Dashboard Panels

### Prediction Trend by Model

Shows live prediction volume over time, split by model:

```text
firewall
web
ssh
```

Use it to confirm that all three live scoring streams are active.

### Prediction Mix by Model

Stacked bars showing:

```text
Normal vs Anomaly
```

Use it to compare which model is producing the most anomalies.

### Average Risk by Model

Shows average `risk_score` by model on a 0-1 scale.

Higher values mean the model considers recent events/windows more unusual.

### Raw Log Volume by Type

Shows raw log ingestion by type:

```text
firewall
web
ssh
```

Use it to confirm Logstash is tailing raw logs.

### Firewall Actions

Groups firewall raw logs by:

```text
action
```

Example values:

```text
allow
deny
drop
reset-both
```

### Web Status Outcomes

Groups Web raw logs by normalized:

```text
status_label
```

Values:

```text
success       HTTP 2xx
redirect      HTTP 3xx
client_error  HTTP 4xx
server_error  HTTP 5xx
other
```

### SSH Login Status

Groups SSH raw logs by normalized:

```text
status_label
```

Values:

```text
accepted
failed
invalid_user
auth_failure
connection
command
other
```

### Top SSH Source IP Risk

Ranks SSH source IPs by average `risk_score`.

Use it to identify repeated suspicious source IPs.

## Useful Discover Filters

Prediction anomalies only:

```text
event_category : "prediction" and is_anomaly : true
```

Web client errors:

```text
model_type : "web" and status_label : "client_error"
```

Web server errors:

```text
model_type : "web" and status_label : "server_error"
```

SSH invalid users:

```text
model_type : "ssh" and status_label : "invalid_user"
```

Firewall non-allow actions:

```text
model_type : "firewall" and not action : "allow"
```

High-risk predictions:

```text
event_category : "prediction" and risk_score >= 0.55
```

## Time Picker

The dashboard defaults to:

```text
Last 15 minutes
```

If old demo data is not visible, widen the time picker:

```text
Last 24 hours
Last 7 days
```

For live testing, keep the refresh interval enabled.

## Updating The Dashboard

After changing Logstash parsing or Kibana visualizations:

```powershell
.\elk\setup_kibana.ps1
```

The script:

1. Waits for Elasticsearch and Kibana.
2. Installs index templates.
3. Backfills Web/SSH `status_label` fields when possible.
4. Installs Kibana data views and dashboards.
5. Starts or restarts Logstash.

## Resetting Kibana/Elasticsearch State

```powershell
.\elk\stop_elk.ps1 -Reset
.\elk\start_elk.ps1
.\elk\setup_kibana.ps1
```

Then generate fresh live data:

```powershell
python .\live\generate_logs.py --reset --count 100 --interval 0.5 --attack-rate 0.3
```
