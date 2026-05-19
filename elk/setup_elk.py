from __future__ import annotations

import base64
import json
import os
import sys
import time
from http.client import RemoteDisconnected
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200").rstrip("/")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601").rstrip("/")
ELASTIC_USER = os.environ.get("ELASTIC_USER", "")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "")
KIBANA_VERSION = os.environ.get("ELASTIC_VERSION", "9.4.0")


def auth_header() -> dict[str, str]:
    if not ELASTIC_USER:
        return {}
    token = base64.b64encode(f"{ELASTIC_USER}:{ELASTIC_PASSWORD}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def request_json(method: str, url: str, body: dict | None = None, *, kibana: bool = False) -> dict:
    headers = {"Content-Type": "application/json", **auth_header()}
    if kibana:
        headers["kbn-xsrf"] = "true"
    data = json.dumps(body).encode() if body is not None else None
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=20) as response:
            payload = response.read()
    except HTTPError as exc:
        detail = exc.read().decode(errors="ignore")
        raise RuntimeError(f"{method} {url} failed with HTTP {exc.code}: {detail}") from exc
    if not payload:
        return {}
    return json.loads(payload.decode())


def wait_for(name: str, url: str, *, kibana: bool = False, timeout: int = 180) -> None:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            request_json("GET", url, kibana=kibana)
            print(f"{name} is reachable")
            return
        except (RuntimeError, URLError, TimeoutError, RemoteDisconnected, ConnectionError, OSError) as exc:
            last_error = str(exc)
            time.sleep(3)
    raise RuntimeError(f"Timed out waiting for {name}: {last_error}")


def put_index_templates() -> None:
    common_settings = {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    }
    keyword = {"type": "keyword"}
    keyword_text = {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}
    ip_field = {"type": "ip", "ignore_malformed": True}

    templates = {
        "cyber-live-scores-template": {
            "index_patterns": ["cyber-live-scores-*"],
            "priority": 500,
            "template": {
                "settings": common_settings,
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "scored_at": {"type": "date"},
                        "event_category": keyword,
                        "model": keyword,
                        "action": keyword,
                        "host": keyword,
                        "url": keyword,
                        "client_ip": ip_field,
                        "url_path": keyword,
                        "http_method": keyword,
                        "source_ip": ip_field,
                        "source_port": {"type": "integer"},
                        "destination_port": {"type": "integer"},
                        "bytes": {"type": "long"},
                        "packets": {"type": "long"},
                        "elapsed_time_sec": {"type": "float"},
                        "event_type": keyword,
                        "ssh_sensor": keyword,
                        "username": keyword,
                        "status": {"type": "integer"},
                        "http_status": {"type": "integer"},
                        "response_bytes": {"type": "long"},
                        "status_label": keyword_text,
                        "window_events": {"type": "integer"},
                        "prediction": {"type": "integer"},
                        "is_anomaly": {"type": "boolean"},
                        "anomaly_score": {"type": "float"},
                        "risk_score": {"type": "float"},
                        "sigma_match": {"type": "boolean"},
                        "sigma_rule_count": {"type": "integer"},
                        "sigma_engine": keyword,
                        "sigma_rule_id": keyword,
                        "sigma_rule_title": keyword_text,
                        "sigma_rule_level": keyword,
                        "sigma_rule_tags": keyword,
                    },
                },
            },
        },
        "cyber-live-raw-firewall-template": {
            "index_patterns": ["cyber-live-raw-firewall-*"],
            "priority": 500,
            "template": {
                "settings": common_settings,
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_category": keyword,
                        "model_type": keyword,
                        "action": keyword,
                        "source_port": {"type": "integer"},
                        "destination_port": {"type": "integer"},
                        "nat_source_port": {"type": "integer"},
                        "nat_destination_port": {"type": "integer"},
                        "bytes": {"type": "long"},
                        "bytes_sent": {"type": "long"},
                        "bytes_received": {"type": "long"},
                        "packets": {"type": "long"},
                        "elapsed_time_sec": {"type": "float"},
                        "pkts_sent": {"type": "long"},
                        "pkts_received": {"type": "long"},
                    },
                },
            },
        },
        "cyber-live-raw-web-template": {
            "index_patterns": ["cyber-live-raw-web-*"],
            "priority": 500,
            "template": {
                "settings": common_settings,
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_category": keyword,
                        "model_type": keyword,
                        "client_ip": ip_field,
                        "http_method": keyword,
                        "http_status": {"type": "integer"},
                        "status_label": keyword_text,
                        "http_version": keyword,
                        "url_path": keyword,
                        "response_bytes": {"type": "long"},
                    },
                },
            },
        },
        "cyber-live-raw-ssh-template": {
            "index_patterns": ["cyber-live-raw-ssh-*"],
            "priority": 500,
            "template": {
                "settings": common_settings,
                "mappings": {
                    "dynamic": True,
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "event_category": keyword,
                        "model_type": keyword,
                        "ssh_sensor": keyword,
                        "ssh_pid": {"type": "integer"},
                        "event_type": keyword,
                        "status_label": keyword_text,
                        "source_ip": ip_field,
                        "source_port": {"type": "integer"},
                        "username": keyword,
                    },
                },
            },
        },
    }

    for name, template in templates.items():
        request_json("PUT", f"{ELASTICSEARCH_URL}/_index_template/{name}", template)
        print(f"installed index template: {name}")


def update_by_query(index_pattern: str, body: dict, description: str) -> None:
    try:
        response = request_json(
            "POST",
            (
                f"{ELASTICSEARCH_URL}/{index_pattern}/_update_by_query"
                "?conflicts=proceed&refresh=true&ignore_unavailable=true"
            ),
            body,
        )
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            print(f"skipped status backfill: {description} has no matching indices yet")
            return
        raise
    updated = response.get("updated", 0)
    print(f"backfilled status labels for {description}: {updated} documents")


def backfill_status_labels() -> None:
    web_script = """
        def code = null;
        if (ctx._source.containsKey('http_status') && ctx._source.http_status != null) {
          code = ctx._source.http_status;
        } else if (ctx._source.containsKey('status') && ctx._source.status != null) {
          code = ctx._source.status;
          ctx._source.http_status = code;
        } else if (ctx._source.containsKey('message') && ctx._source.message != null) {
          def msg = ctx._source.message;
          int quote = msg.lastIndexOf('"');
          if (quote >= 0 && quote + 1 < msg.length()) {
            def tail = msg.substring(quote + 1).trim();
            int space = tail.indexOf(' ');
            if (space > 0) {
              try {
                code = Integer.parseInt(tail.substring(0, space));
                ctx._source.http_status = code;
              } catch (Exception e) {
                code = null;
              }
            }
          }
        }

        if (code == null) {
          ctx._source.status_label = 'other';
        } else if (code >= 200 && code < 300) {
          ctx._source.status_label = 'success';
        } else if (code >= 300 && code < 400) {
          ctx._source.status_label = 'redirect';
        } else if (code >= 400 && code < 500) {
          ctx._source.status_label = 'client_error';
        } else if (code >= 500 && code < 600) {
          ctx._source.status_label = 'server_error';
        } else {
          ctx._source.status_label = 'other';
        }
    """
    ssh_script = """
        def event = ctx._source.containsKey('event_type') ? ctx._source.event_type : null;
        if (ctx._source.containsKey('message') && ctx._source.message != null) {
          def msg = ctx._source.message;
          if (msg.contains('Accepted ')) {
            event = 'accepted_login';
          } else if (msg.contains('Failed password for invalid user')) {
            event = 'failed_login_invalid';
          } else if (msg.contains('Failed password')) {
            event = 'failed_login';
          } else if (msg.contains('Invalid user ')) {
            event = 'invalid_user';
          } else if (msg.contains('authentication failure;')) {
            event = 'auth_failure';
          } else if (msg.contains('Did not receive identification string')) {
            event = 'connection_scan';
          } else if (msg.contains('Connection closed by')) {
            event = 'connection_closed';
          }
          if (event != null) {
            ctx._source.event_type = event;
          }
        }

        if (event == 'accepted_login') {
          ctx._source.status_label = 'accepted';
        } else if (event == 'failed_login') {
          ctx._source.status_label = 'failed';
        } else if (event == 'failed_login_invalid' || event == 'invalid_user') {
          ctx._source.status_label = 'invalid_user';
        } else if (event == 'auth_failure') {
          ctx._source.status_label = 'auth_failure';
        } else if (event == 'connection' || event == 'connection_scan' || event == 'connection_closed') {
          ctx._source.status_label = 'connection';
        } else if (event == 'command') {
          ctx._source.status_label = 'command';
        } else {
          ctx._source.status_label = 'other';
        }
    """
    missing_or_other_status_query = {
        "query": {
            "bool": {
                "minimum_should_match": 1,
                "should": [
                    {"bool": {"must_not": [{"exists": {"field": "status_label"}}]}},
                    {"term": {"status_label": "other"}},
                    {"term": {"status_label.keyword": "other"}},
                ],
            }
        }
    }
    update_by_query(
        "cyber-live-raw-web-*",
        {"script": {"lang": "painless", "source": web_script}, **missing_or_other_status_query},
        "raw web logs",
    )
    update_by_query(
        "cyber-live-scores-web-*",
        {"script": {"lang": "painless", "source": web_script}, **missing_or_other_status_query},
        "web predictions",
    )
    update_by_query(
        "cyber-live-raw-ssh-*",
        {"script": {"lang": "painless", "source": ssh_script}, **missing_or_other_status_query},
        "raw ssh logs",
    )
    update_by_query(
        "cyber-live-scores-ssh-*",
        {"script": {"lang": "painless", "source": ssh_script}, **missing_or_other_status_query},
        "ssh predictions",
    )


def vega_spec(
    *,
    title: str,
    index: str,
    aggregations: dict,
    data_property: str,
    mark: str | dict,
    encoding: dict,
    transform: list[dict] | None = None,
    width: int = 420,
    height: int = 180,
) -> dict:
    spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "url": {
                "%context%": True,
                "%timefield%": "@timestamp",
                "index": index,
                "body": {
                    "size": 0,
                    "aggs": aggregations,
                },
            },
            "format": {"property": data_property},
        },
        "mark": mark,
        "encoding": encoding,
        "width": width,
        "height": height,
        "config": {
            "view": {"stroke": None},
            "axis": {"labelFontSize": 11, "titleFontSize": 12, "grid": True, "gridOpacity": 0.18},
            "legend": {"labelFontSize": 11, "titleFontSize": 12},
        },
    }
    if transform:
        spec["transform"] = transform
    return spec


def resilient_terms(field: str, *, size: int = 10, order: dict | None = None) -> dict:
    keyword_field = f"{field}.keyword"
    terms = {
        "script": {
            "lang": "painless",
            "source": (
                "if (doc.containsKey(params.keyword_field) && doc[params.keyword_field].size() != 0) "
                "{ return doc[params.keyword_field].value; } "
                "if (doc.containsKey(params.field) && doc[params.field].size() != 0) "
                "{ return doc[params.field].value; } "
                "return 'unknown';"
            ),
            "params": {
                "field": field,
                "keyword_field": keyword_field,
            },
        },
        "size": size,
    }
    if order:
        terms["order"] = order
    return {"terms": terms}


def visualization_attributes(title: str, spec: dict, description: str = "") -> dict:
    return {
        "title": title,
        "description": description,
        "visState": json.dumps(
            {
                "title": title,
                "type": "vega",
                "params": {
                    "spec": json.dumps(spec, indent=2),
                },
            }
        ),
        "uiStateJSON": "{}",
        "version": 1,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": "{}",
        },
    }


def create_saved_object(object_type: str, object_id: str, attributes: dict, references: list[dict] | None = None) -> None:
    body = {
        "attributes": attributes,
        "references": references or [],
    }
    request_json(
        "POST",
        f"{KIBANA_URL}/api/saved_objects/{object_type}/{object_id}?overwrite=true",
        body,
        kibana=True,
    )
    print(f"installed Kibana {object_type}: {object_id}")


def create_data_views() -> None:
    data_views = {
        "cyber-live-scores": "cyber-live-scores-*",
        "cyber-live-raw": "cyber-live-raw-*",
        "cyber-live-raw-firewall": "cyber-live-raw-firewall-*",
        "cyber-live-raw-web": "cyber-live-raw-web-*",
        "cyber-live-raw-ssh": "cyber-live-raw-ssh-*",
    }
    for object_id, title in data_views.items():
        create_saved_object(
            "index-pattern",
            object_id,
            {
                "title": title,
                "timeFieldName": "@timestamp",
                "allowNoIndex": True,
            },
        )


def build_visualizations() -> list[str]:
    visualizations: list[tuple[str, str, dict]] = []

    visualizations.append(
        (
            "cyber-live-score-volume",
            "Prediction Trend by Model",
            vega_spec(
                title="Prediction Trend by Model",
                index="cyber-live-scores-*",
                aggregations={
                    "events_over_time": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "fixed_interval": "1m",
                            "min_doc_count": 0,
                        },
                        "aggs": {
                            "by_model": resilient_terms("model", size=10),
                        },
                    }
                },
                data_property="aggregations.events_over_time.buckets",
                mark={"type": "line", "point": True, "strokeWidth": 2},
                transform=[
                    {"flatten": ["by_model.buckets"], "as": ["model_bucket"]},
                    {"calculate": "datum.model_bucket.key", "as": "model"},
                    {"calculate": "datum.model_bucket.doc_count", "as": "predictions"},
                ],
                encoding={
                    "x": {"field": "key_as_string", "type": "temporal", "title": "Time"},
                    "y": {"field": "predictions", "type": "quantitative", "title": "Predictions"},
                    "color": {
                        "field": "model",
                        "type": "nominal",
                        "title": "Model",
                        "scale": {"range": ["#2563eb", "#0f766e", "#f97316"]},
                    },
                    "tooltip": [
                        {"field": "key_as_string", "type": "temporal", "title": "Time"},
                        {"field": "model", "type": "nominal", "title": "Model"},
                        {"field": "predictions", "type": "quantitative", "title": "Predictions"},
                    ],
                },
                width=900,
                height=220,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-anomalies-by-model",
            "Prediction Mix by Model",
            vega_spec(
                title="Prediction Mix by Model",
                index="cyber-live-scores-*",
                aggregations={
                    "models": {
                        **resilient_terms("model", size=10, order={"_count": "desc"}),
                        "aggs": {
                            "normal": {"filter": {"term": {"is_anomaly": False}}},
                            "anomaly": {"filter": {"term": {"is_anomaly": True}}},
                        },
                    }
                },
                data_property="aggregations.models.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 2},
                transform=[
                    {"calculate": "datum.normal.doc_count", "as": "normal_count"},
                    {"calculate": "datum.anomaly.doc_count", "as": "anomaly_count"},
                    {"fold": ["normal_count", "anomaly_count"], "as": ["outcome_key", "count"]},
                    {"calculate": "datum.outcome_key == 'anomaly_count' ? 'Anomaly' : 'Normal'", "as": "outcome"},
                ],
                encoding={
                    "x": {"field": "key", "type": "nominal", "title": "Model", "sort": "-y"},
                    "y": {"field": "count", "type": "quantitative", "title": "Predictions", "stack": "zero"},
                    "color": {
                        "field": "outcome",
                        "type": "nominal",
                        "title": "Outcome",
                        "scale": {"domain": ["Normal", "Anomaly"], "range": ["#16a34a", "#dc2626"]},
                    },
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Model"},
                        {"field": "outcome", "type": "nominal", "title": "Outcome"},
                        {"field": "count", "type": "quantitative", "title": "Count"},
                    ],
                },
                width=420,
                height=180,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-average-risk-by-model",
            "Average Risk by Model",
            vega_spec(
                title="Average Risk by Model",
                index="cyber-live-scores-*",
                aggregations={
                    "models": {
                        **resilient_terms("model", size=10),
                        "aggs": {"avg_risk": {"avg": {"field": "risk_score"}}},
                    }
                },
                data_property="aggregations.models.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "y": {"field": "key", "type": "nominal", "title": "Model", "sort": "-x"},
                    "x": {
                        "field": "avg_risk.value",
                        "type": "quantitative",
                        "title": "Average risk",
                        "scale": {"domain": [0, 1]},
                    },
                    "color": {
                        "field": "avg_risk.value",
                        "type": "quantitative",
                        "title": "Risk",
                        "scale": {"scheme": "orangered"},
                    },
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Model"},
                        {"field": "avg_risk.value", "type": "quantitative", "title": "Average risk"},
                    ],
                },
                width=420,
                height=180,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-raw-events-by-type",
            "Raw Log Volume by Type",
            vega_spec(
                title="Raw Log Volume by Type",
                index="cyber-live-raw-*",
                aggregations={
                    "types": resilient_terms("model_type", size=10, order={"_count": "desc"})
                },
                data_property="aggregations.types.buckets",
                mark={"type": "arc", "innerRadius": 45, "outerRadius": 82},
                encoding={
                    "theta": {"field": "doc_count", "type": "quantitative", "title": "Raw events"},
                    "color": {
                        "field": "key",
                        "type": "nominal",
                        "title": "Log type",
                        "scale": {"range": ["#2563eb", "#0f766e", "#f97316"]},
                    },
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Log type"},
                        {"field": "doc_count", "type": "quantitative", "title": "Raw events"},
                    ],
                },
                width=300,
                height=175,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-firewall-actions",
            "Firewall Actions",
            vega_spec(
                title="Firewall Actions",
                index="cyber-live-raw-firewall-*",
                aggregations={
                    "actions": resilient_terms("action", size=10, order={"_count": "desc"})
                },
                data_property="aggregations.actions.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "y": {"field": "key", "type": "nominal", "title": "Action", "sort": "-x"},
                    "x": {"field": "doc_count", "type": "quantitative", "title": "Events"},
                    "color": {"value": "#0f766e"},
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Action"},
                        {"field": "doc_count", "type": "quantitative", "title": "Events"},
                    ],
                },
                width=310,
                height=175,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-web-status-codes",
            "Web Status Outcomes",
            vega_spec(
                title="Web Status Outcomes",
                index="cyber-live-raw-web-*",
                aggregations={
                    "statuses": resilient_terms("status_label", size=10, order={"_count": "desc"})
                },
                data_property="aggregations.statuses.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "x": {"field": "key", "type": "nominal", "title": "Status", "sort": "-y"},
                    "y": {"field": "doc_count", "type": "quantitative", "title": "Events"},
                    "color": {
                        "field": "key",
                        "type": "nominal",
                        "title": "Status",
                        "scale": {
                            "domain": ["success", "redirect", "client_error", "server_error", "other"],
                            "range": ["#16a34a", "#2563eb", "#f97316", "#dc2626", "#64748b"],
                        },
                    },
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Status"},
                        {"field": "doc_count", "type": "quantitative", "title": "Events"},
                    ],
                },
                width=310,
                height=175,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-ssh-event-types",
            "SSH Login Status",
            vega_spec(
                title="SSH Login Status",
                index="cyber-live-raw-ssh-*",
                aggregations={
                    "events": resilient_terms("status_label", size=10, order={"_count": "desc"})
                },
                data_property="aggregations.events.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "y": {"field": "key", "type": "nominal", "title": "Status", "sort": "-x"},
                    "x": {"field": "doc_count", "type": "quantitative", "title": "Events"},
                    "color": {"value": "#0891b2"},
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Status"},
                        {"field": "doc_count", "type": "quantitative", "title": "Events"},
                    ],
                },
                width=420,
                height=180,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-top-ssh-risk",
            "Top SSH Source IP Risk",
            vega_spec(
                title="Top SSH Source IP Risk",
                index="cyber-live-scores-ssh-*",
                aggregations={
                    "sources": {
                        **resilient_terms("source_ip", size=10),
                        "aggs": {"avg_risk": {"avg": {"field": "risk_score"}}},
                    }
                },
                data_property="aggregations.sources.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "y": {"field": "key", "type": "nominal", "title": "Source IP", "sort": "-x"},
                    "x": {
                        "field": "avg_risk.value",
                        "type": "quantitative",
                        "title": "Average risk",
                        "scale": {"domain": [0, 1]},
                    },
                    "color": {
                        "field": "avg_risk.value",
                        "type": "quantitative",
                        "title": "Risk",
                        "scale": {"scheme": "redyellowgreen", "reverse": True},
                    },
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Source IP"},
                        {"field": "avg_risk.value", "type": "quantitative", "title": "Average risk"},
                        {"field": "doc_count", "type": "quantitative", "title": "Scored windows"},
                    ],
                },
                width=420,
                height=180,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-sigma-hits-by-rule",
            "Sigma Rule Hits by Rule",
            vega_spec(
                title="Sigma Rule Hits by Rule",
                index="cyber-live-scores-*",
                aggregations={
                    "sigma_hits": {
                        "filter": {"term": {"sigma_match": True}},
                        "aggs": {
                            "rules": resilient_terms("sigma_rule_id", size=12, order={"_count": "desc"})
                        },
                    }
                },
                data_property="aggregations.sigma_hits.rules.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "y": {"field": "key", "type": "nominal", "title": "Sigma rule", "sort": "-x"},
                    "x": {"field": "doc_count", "type": "quantitative", "title": "Hits"},
                    "color": {"value": "#7c3aed"},
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Rule"},
                        {"field": "doc_count", "type": "quantitative", "title": "Hits"},
                    ],
                },
                width=420,
                height=180,
            ),
        )
    )

    visualizations.append(
        (
            "cyber-live-sigma-hits-by-severity",
            "Sigma Rule Hits by Severity",
            vega_spec(
                title="Sigma Rule Hits by Severity",
                index="cyber-live-scores-*",
                aggregations={
                    "sigma_hits": {
                        "filter": {"term": {"sigma_match": True}},
                        "aggs": {
                            "levels": resilient_terms("sigma_rule_level", size=8, order={"_count": "desc"})
                        },
                    }
                },
                data_property="aggregations.sigma_hits.levels.buckets",
                mark={"type": "bar", "cornerRadiusEnd": 3},
                encoding={
                    "x": {"field": "key", "type": "nominal", "title": "Severity", "sort": "-y"},
                    "y": {"field": "doc_count", "type": "quantitative", "title": "Hits"},
                    "color": {
                        "field": "key",
                        "type": "nominal",
                        "title": "Severity",
                        "scale": {
                            "domain": ["low", "medium", "high", "critical"],
                            "range": ["#65a30d", "#f97316", "#dc2626", "#7f1d1d"],
                        },
                    },
                    "tooltip": [
                        {"field": "key", "type": "nominal", "title": "Severity"},
                        {"field": "doc_count", "type": "quantitative", "title": "Hits"},
                    ],
                },
                width=420,
                height=180,
            ),
        )
    )

    ids: list[str] = []
    for object_id, title, spec in visualizations:
        create_saved_object(
            "visualization",
            object_id,
            visualization_attributes(title, spec, "Generated by elk/setup_elk.py"),
        )
        ids.append(object_id)
    return ids


def create_dashboard(visualization_ids: list[str]) -> None:
    panels = []
    references = []
    layouts = [
        {"x": 0, "y": 0, "w": 48, "h": 13},
        {"x": 0, "y": 13, "w": 24, "h": 12},
        {"x": 24, "y": 13, "w": 24, "h": 12},
        {"x": 0, "y": 25, "w": 16, "h": 12},
        {"x": 16, "y": 25, "w": 16, "h": 12},
        {"x": 32, "y": 25, "w": 16, "h": 12},
        {"x": 0, "y": 37, "w": 24, "h": 12},
        {"x": 24, "y": 37, "w": 24, "h": 12},
        {"x": 0, "y": 49, "w": 24, "h": 12},
        {"x": 24, "y": 49, "w": 24, "h": 12},
    ]
    for index, object_id in enumerate(visualization_ids):
        panel_ref = f"panel_{index}"
        layout = layouts[index] if index < len(layouts) else {"x": 0, "y": index * 12, "w": 24, "h": 12}
        references.append({"name": panel_ref, "type": "visualization", "id": object_id})
        panels.append(
            {
                "version": KIBANA_VERSION,
                "type": "visualization",
                "panelIndex": str(index + 1),
                "panelRefName": panel_ref,
                "embeddableConfig": {},
                "gridData": {
                    "x": layout["x"],
                    "y": layout["y"],
                    "w": layout["w"],
                    "h": layout["h"],
                    "i": str(index + 1),
                },
            }
        )

    create_saved_object(
        "dashboard",
        "cyber-live-security-dashboard",
        {
            "title": "SSH/Web/Firewall Live Security Dashboard",
            "description": "Live raw logs and model prediction monitoring for Firewall, Web, and SSH.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps(
                {
                    "useMargins": True,
                    "syncColors": False,
                    "hidePanelTitles": False,
                }
            ),
            "timeRestore": True,
            "timeFrom": "now-15m",
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 5000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {
                        "query": {"language": "kuery", "query": ""},
                        "filter": [],
                    }
                )
            },
        },
        references=references,
    )


def main() -> int:
    print(f"Elasticsearch: {ELASTICSEARCH_URL}")
    print(f"Kibana:        {KIBANA_URL}")
    wait_for("Elasticsearch", f"{ELASTICSEARCH_URL}/")
    wait_for("Kibana", f"{KIBANA_URL}/api/status", kibana=True)
    put_index_templates()
    backfill_status_labels()
    create_data_views()
    visualization_ids = build_visualizations()
    create_dashboard(visualization_ids)
    print("\nKibana dashboard installed: SSH/Web/Firewall Live Security Dashboard")
    print(f"Open: {KIBANA_URL}/app/dashboards#/view/cyber-live-security-dashboard")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"setup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
