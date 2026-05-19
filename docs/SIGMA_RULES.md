# Sigma Rule Options And Added Rules

Yes, Sigma-style rules can be added to this project.

## Possible Approaches

| Option | How it works | Pros | Tradeoff |
| --- | --- | --- | --- |
| Logstash-native rules | Store Sigma YAML and mirror the detection logic in `cyber-live.conf` | Simple, live, no new service | Rule logic must be manually mirrored |
| pySigma / sigma-cli | Convert Sigma YAML to Elasticsearch DSL or KQL | Closer to official Sigma workflow | Adds dependency and conversion step |
| Python rule engine | Evaluate rules inside `live\listen_and_score.py` | Easy to test with model scores | Detection is outside Logstash |
| ElastAlert-style alerts | Run queries against Elasticsearch | Good alerting workflow | Extra service to run |
| Elastic Security rules | Use Elastic detection engine | Strong UI if available | Depends on Elastic features/configuration |

## Implemented Now

The project currently uses the **Python rule engine** option.

Rule files:

```text
sigma\rules\firewall_denied_or_dropped.yml
sigma\rules\firewall_large_transfer.yml
sigma\rules\firewall_sensitive_destination_port.yml
sigma\rules\ssh_authentication_failure.yml
sigma\rules\ssh_identification_scan.yml
sigma\rules\ssh_invalid_user.yml
sigma\rules\web_admin_interface_probe.yml
sigma\rules\web_path_traversal_probe.yml
sigma\rules\web_sensitive_file_probe.yml
```

The Python engine loads those files from:

```text
live\sigma_rule_engine.py
live\listen_and_score.py
```

When a rule matches, the live prediction JSONL event is enriched with:

```text
sigma_match
sigma_rule_count
sigma_engine
sigma_rule_id
sigma_rule_title
sigma_rule_level
sigma_rule_tags
```

For Sigma fields, Logstash ingests the already enriched JSONL prediction files. Raw logs are still indexed normally, but the rule decisions are made in Python, not in Logstash.

## Rules

| Rule ID | Type | Level | Meaning |
| --- | --- | --- | --- |
| `sigma-web-path-traversal-probe` | Web | high | URL contains traversal or sensitive OS file probes |
| `sigma-web-sensitive-file-probe` | Web | high | URL requests `.env`, `.git/config`, config files |
| `sigma-web-admin-interface-probe` | Web | medium | URL targets admin panels such as `wp-login.php`, `phpmyadmin`, `manager/html` |
| `sigma-ssh-invalid-user` | SSH | medium | SSH invalid user or failed invalid user attempt |
| `sigma-ssh-authentication-failure` | SSH | low | SSH authentication failure or failed known-user login |
| `sigma-ssh-identification-scan` | SSH | medium | SSH identification string scan |
| `sigma-firewall-denied-or-dropped` | Firewall | medium | Firewall action is not `allow` |
| `sigma-firewall-sensitive-destination-port` | Firewall | medium | Traffic targets sensitive ports such as 22, 23, 445, 3389, 9200 |
| `sigma-firewall-large-transfer` | Firewall | low | Firewall row has more than 100000 bytes |

## Kibana Filters

The Kibana setup also creates:

```text
Sigma Rule Hits by Rule
Sigma Rule Hits by Severity
```

All Sigma matches:

```text
sigma_match : true
```

High severity:

```text
sigma_rule_level : "high"
```

One rule:

```text
sigma_rule_id : "sigma-web-path-traversal-probe"
```

Matched SSH detections:

```text
model : "ssh" and sigma_match : true
```
