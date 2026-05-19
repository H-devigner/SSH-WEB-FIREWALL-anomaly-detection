# Sigma Rules

This folder stores Sigma-style YAML detections used by the live Logstash pipeline.

Current implementation:

```text
sigma\rules\*.yml
  -> manually mirrored in elk\logstash\pipeline\cyber-live.conf
  -> matching raw events receive sigma_* fields
  -> events remain in cyber-live-raw-* indices
```

Why this approach:

- no extra service is required;
- rules are visible as portable YAML;
- Logstash enriches events live before Elasticsearch indexing;
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
- create a Python rule engine in `live\listen_and_score.py`;
- use ElastAlert/OpenSearch-style alerting on Elasticsearch queries;
- use Elastic Security detection rules if the Elastic distribution and license features are available.
