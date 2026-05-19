# Sigma Rules

This folder stores Sigma-style YAML detections used by the Python live rule engine.

Current implementation:

```text
sigma\rules\*.yml
  -> loaded by live\sigma_rule_engine.py
  -> evaluated inside live\listen_and_score.py
  -> matching prediction events receive sigma_* fields
  -> Logstash ingests enriched JSONL score files
```

Why this approach:

- no extra service is required;
- rules are visible as portable YAML;
- Python can combine rule hits with model prediction scores;
- Kibana can filter on `sigma_match`, `sigma_rule_id`, `sigma_rule_title`, `sigma_rule_level`, and `sigma_rule_tags`.

Useful Kibana filters:

```text
sigma_match : true
```

```text
sigma_rule_level : "high"
```

```text
sigma_rule_id : "sigma-web-path-traversal-probe"
```

Other possible approaches for later:

- use `sigma-cli` / pySigma to convert official Sigma rules to Elasticsearch DSL or KQL;
- use ElastAlert/OpenSearch-style alerting on Elasticsearch queries;
- use Elastic Security detection rules if the Elastic distribution and license features are available.
