LIVE FILE SCORING
-----------------
This folder contains a local file-based live demo:

1. generate_logs.py writes synthetic Firewall, Web, and SSH logs.
2. listen_and_score.py tails those files, aggregates features where needed,
   scores each event/window with the matching trained model, and writes JSONL
   score outputs.

No Logstash or API server is required.

Default log files:
- Firewall/live_logs/firewall_live.csv
- WEB LOGS MODEL/live_logs/web_access.log
- SSH/live_logs/ssh_auth.log

Default score files:
- Firewall/live_scores/firewall_scores.jsonl
- WEB LOGS MODEL/live_scores/web_scores.jsonl
- SSH/live_scores/ssh_scores.jsonl

Web and SSH score outputs include `status_label` for readable dashboard
grouping. Web labels are `success`, `redirect`, `client_error`,
`server_error`, or `other`; SSH labels include `accepted`, `failed`,
`invalid_user`, `auth_failure`, `connection`, `command`, and `other`.

Example, two terminals:

Terminal 1:
python live/listen_and_score.py --from-start

Terminal 2:
python live/generate_logs.py --reset --count 30 --interval 0.5

One-shot test:
python live/generate_logs.py --reset --count 10 --interval 0
python live/listen_and_score.py --from-start --max-events 30

ELK integration:
See ../elk/README.md for Docker Compose, Logstash file ingestion, Elasticsearch
indices, and the Kibana live security dashboard.
