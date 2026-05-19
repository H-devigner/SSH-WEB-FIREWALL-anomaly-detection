from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SigmaRule:
    rule_id: str
    title: str
    level: str
    tags: list[str]
    detection: dict[str, Any]
    source_model: str | None = None


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return ""
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _yaml_lines(path: Path) -> list[tuple[int, str]]:
    rows: list[tuple[int, str]] = []
    with path.open(encoding="utf-8") as handle:
        for raw in handle:
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip(" "))
            rows.append((indent, raw.strip()))
    return rows


def _parse_block(rows: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(rows) or rows[index][0] < indent:
        return {}, index

    if rows[index][0] == indent and rows[index][1].startswith("- "):
        values = []
        while index < len(rows) and rows[index][0] == indent and rows[index][1].startswith("- "):
            item = rows[index][1][2:].strip()
            if item:
                values.append(_parse_scalar(item))
                index += 1
            else:
                value, index = _parse_block(rows, index + 1, indent + 2)
                values.append(value)
        return values, index

    values: dict[str, Any] = {}
    while index < len(rows) and rows[index][0] == indent and not rows[index][1].startswith("- "):
        key, separator, rest = rows[index][1].partition(":")
        if not separator:
            raise ValueError(f"Invalid YAML line: {rows[index][1]}")
        key = key.strip()
        rest = rest.strip()
        if rest:
            values[key] = _parse_scalar(rest)
            index += 1
        else:
            values[key], index = _parse_block(rows, index + 1, indent + 2)
    return values, index


def load_simple_yaml(path: Path) -> dict[str, Any]:
    rows = _yaml_lines(path)
    parsed, index = _parse_block(rows, 0, 0)
    if index != len(rows):
        raise ValueError(f"Could not parse full YAML file: {path}")
    if not isinstance(parsed, dict):
        raise ValueError(f"Expected YAML mapping in {path}")
    return parsed


def source_model_from_logsource(logsource: dict[str, Any]) -> str | None:
    product = str(logsource.get("product", "")).lower()
    service = str(logsource.get("service", "")).lower()
    if product == "firewall":
        return "firewall"
    if product == "webserver":
        return "web"
    if service == "sshd":
        return "ssh"
    return None


def load_rules(rules_dir: Path) -> list[SigmaRule]:
    rules: list[SigmaRule] = []
    for path in sorted(rules_dir.glob("*.yml")):
        raw = load_simple_yaml(path)
        rule_id = str(raw.get("id", path.stem))
        title = str(raw.get("title", rule_id))
        level = str(raw.get("level", "informational"))
        tags = raw.get("tags") or []
        if isinstance(tags, str):
            tags = [tags]
        detection = raw.get("detection") or {}
        if not isinstance(detection, dict):
            raise ValueError(f"Invalid detection block in {path}")
        rules.append(
            SigmaRule(
                rule_id=rule_id,
                title=title,
                level=level,
                tags=[str(tag) for tag in tags],
                detection=detection,
                source_model=source_model_from_logsource(raw.get("logsource") or {}),
            )
        )
    return rules


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [value]


def _numeric(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _equals(actual: Any, expected: Any) -> bool:
    actual_number = _numeric(actual)
    expected_number = _numeric(expected)
    if actual_number is not None and expected_number is not None:
        return actual_number == expected_number
    return str(actual).lower() == str(expected).lower()


def _match_one(actual: Any, expected: Any, operator: str) -> bool:
    if actual is None:
        return False
    if operator == "contains":
        return str(expected).lower() in str(actual).lower()
    if operator == "not":
        return not _equals(actual, expected)
    if operator in {"gt", "gte", "lt", "lte"}:
        actual_number = _numeric(actual)
        expected_number = _numeric(expected)
        if actual_number is None or expected_number is None:
            return False
        if operator == "gt":
            return actual_number > expected_number
        if operator == "gte":
            return actual_number >= expected_number
        if operator == "lt":
            return actual_number < expected_number
        return actual_number <= expected_number
    return _equals(actual, expected)


def _field_matches(event: dict[str, Any], expression: str, expected: Any) -> bool:
    if "|" in expression:
        field, operator = expression.split("|", 1)
    else:
        field, operator = expression, "equals"

    actual = event.get(field)
    expected_values = _as_list(expected)
    if operator == "not":
        return all(_match_one(actual, value, operator) for value in expected_values)
    return any(_match_one(actual, value, operator) for value in expected_values)


def _selection_matches(selection: dict[str, Any], event: dict[str, Any]) -> bool:
    return all(_field_matches(event, expression, expected) for expression, expected in selection.items())


class SigmaRuleEngine:
    def __init__(self, rules: list[SigmaRule]):
        self.rules = rules

    @classmethod
    def from_directory(cls, rules_dir: Path) -> "SigmaRuleEngine":
        return cls(load_rules(rules_dir))

    def match(self, event: dict[str, Any]) -> list[SigmaRule]:
        matches: list[SigmaRule] = []
        for rule in self.rules:
            if rule.source_model and rule.source_model != event.get("model"):
                continue
            condition = str(rule.detection.get("condition", "")).strip()
            selection = rule.detection.get(condition)
            if isinstance(selection, dict) and _selection_matches(selection, event):
                matches.append(rule)
        return matches


def enrich_event(event: dict[str, Any], matches: list[SigmaRule]) -> dict[str, Any]:
    event["sigma_match"] = bool(matches)
    event["sigma_rule_count"] = len(matches)
    event["sigma_engine"] = "python"
    if matches:
        event["sigma_rule_id"] = [rule.rule_id for rule in matches]
        event["sigma_rule_title"] = [rule.title for rule in matches]
        event["sigma_rule_level"] = [rule.level for rule in matches]
        event["sigma_rule_tags"] = sorted({tag for rule in matches for tag in rule.tags})
    return event
