from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

import pandas as pd


DEFAULT_YEAR = 2013
DEFAULT_WINDOW = "10min"

FEATURES = [
    "connection_count",
    "failed_login_count",
    "auth_failure_count",
    "invalid_user_count",
    "accepted_login_count",
    "command_count",
    "suspicious_command_count",
    "unique_users",
    "unique_passwords",
    "source_port_count",
    "failure_rate",
    "invalid_user_rate",
    "commands_per_accepted",
    "success_after_fail",
    "burst_score",
]

SUSPICIOUS_COMMAND_TOKENS = (
    "wget",
    "curl",
    "chmod",
    "busybox",
    "nc ",
    "netcat",
    "python -",
    "perl ",
    "bash -",
    "/tmp",
    "tftp",
    "scp",
    "ssh ",
)

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
AUTH_PREFIX_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) "
    r"(?P<clock>\d{2}:\d{2}:\d{2}) (?P<sensor>\S+) "
    r"(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?: (?P<message>.*)$"
)
KIPPO_PREFIX_RE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?P<tz>[+-]\d{4}) "
    r"\[(?P<context>[^\]]*)\] (?P<message>.*)$"
)


def _safe_datetime_auth(month: str, day: str, clock: str) -> datetime | None:
    try:
        return datetime.strptime(
            f"{DEFAULT_YEAR} {month} {int(day):02d} {clock}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return None


def _safe_datetime_kippo(stamp: str, tz: str) -> datetime | None:
    try:
        return datetime.strptime(stamp + tz, "%Y-%m-%d %H:%M:%S%z").replace(tzinfo=None)
    except ValueError:
        return None


def _is_suspicious_command(command: str | None) -> int:
    if not command:
        return 0
    lowered = f" {command.lower()} "
    return int(any(token in lowered for token in SUSPICIOUS_COMMAND_TOKENS))


def _event(
    *,
    timestamp: datetime,
    source_ip: str,
    event_type: str,
    sensor_ip: str | None = None,
    source_port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    command: str | None = None,
    raw_line: str = "",
    log_type: str = "auth",
) -> dict:
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "sensor_ip": sensor_ip,
        "event_type": event_type,
        "username": username,
        "password": password,
        "command": command,
        "is_suspicious_command": _is_suspicious_command(command),
        "raw_line": raw_line,
        "log_type": log_type,
    }


def parse_auth_line(line: str) -> dict | None:
    match = AUTH_PREFIX_RE.match(line.strip())
    if not match:
        return None

    timestamp = _safe_datetime_auth(match["month"], match["day"], match["clock"])
    if timestamp is None:
        return None

    message = match["message"]
    sensor_ip = match["sensor"]

    failed = re.search(
        r"Failed password for (?:(invalid user) )?(?P<user>\S+) from "
        r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}) port (?P<port>\d+)",
        message,
    )
    if failed:
        return _event(
            timestamp=timestamp,
            source_ip=failed["ip"],
            source_port=int(failed["port"]),
            sensor_ip=sensor_ip,
            username=failed["user"],
            event_type="failed_login_invalid"
            if failed.group(1)
            else "failed_login",
            raw_line=line.rstrip("\n"),
        )

    invalid = re.search(
        r"Invalid user (?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        message,
    )
    if invalid:
        return _event(
            timestamp=timestamp,
            source_ip=invalid["ip"],
            sensor_ip=sensor_ip,
            username=invalid["user"],
            event_type="invalid_user",
            raw_line=line.rstrip("\n"),
        )

    accepted = re.search(
        r"Accepted \S+ for (?P<user>\S+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3}) "
        r"port (?P<port>\d+)",
        message,
    )
    if accepted:
        return _event(
            timestamp=timestamp,
            source_ip=accepted["ip"],
            source_port=int(accepted["port"]),
            sensor_ip=sensor_ip,
            username=accepted["user"],
            event_type="accepted_login",
            raw_line=line.rstrip("\n"),
        )

    failure = re.search(r"authentication failure; .*rhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})", message)
    if failure:
        user_match = re.search(r"\buser=(?P<user>\S+)", message)
        return _event(
            timestamp=timestamp,
            source_ip=failure["ip"],
            sensor_ip=sensor_ip,
            username=user_match["user"] if user_match else None,
            event_type="auth_failure",
            raw_line=line.rstrip("\n"),
        )

    scan = re.search(
        r"Did not receive identification string from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
        message,
    )
    if scan:
        return _event(
            timestamp=timestamp,
            source_ip=scan["ip"],
            sensor_ip=sensor_ip,
            event_type="connection_scan",
            raw_line=line.rstrip("\n"),
        )

    closed = re.search(r"Connection closed by (?P<ip>(?:\d{1,3}\.){3}\d{1,3})", message)
    if closed:
        return _event(
            timestamp=timestamp,
            source_ip=closed["ip"],
            sensor_ip=sensor_ip,
            event_type="connection_closed",
            raw_line=line.rstrip("\n"),
        )

    return None


def parse_auth_file(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open("r", errors="ignore") as handle:
        for line in handle:
            parsed = parse_auth_line(line)
            if parsed:
                events.append(parsed)
    return events


def parse_kippo_file(path: Path) -> list[dict]:
    events: list[dict] = []
    session_ip: dict[str, str] = {}
    session_port: dict[str, int] = {}
    sensor_ip = path.parent.name

    with path.open("r", errors="ignore") as handle:
        for line in handle:
            match = KIPPO_PREFIX_RE.match(line.strip())
            if not match:
                continue

            timestamp = _safe_datetime_kippo(match["stamp"], match["tz"])
            if timestamp is None:
                continue

            context = match["context"]
            message = match["message"]
            context_ips = IP_RE.findall(context)
            source_ip = context_ips[-1] if context_ips else None
            session_match = re.search(r"(?:HoneyPotTransport|Transport),(\d+)", context)
            session_id = session_match.group(1) if session_match else None

            connection = re.search(
                r"New connection: (?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d+) "
                r".*\[session: (?P<session>\d+)\]",
                message,
            )
            if connection:
                session_ip[connection["session"]] = connection["ip"]
                session_port[connection["session"]] = int(connection["port"])
                events.append(
                    _event(
                        timestamp=timestamp,
                        source_ip=connection["ip"],
                        source_port=int(connection["port"]),
                        sensor_ip=sensor_ip,
                        event_type="connection",
                        raw_line=line.rstrip("\n"),
                        log_type="kippo",
                    )
                )
                continue

            if session_id and session_id in session_ip:
                source_ip = session_ip[session_id]
            if not source_ip:
                continue

            source_port = session_port.get(session_id) if session_id else None

            login = re.search(r"login attempt \[(?P<creds>.*)\] (?P<result>succeeded|failed)", message)
            if login:
                creds = login["creds"]
                username, password = (creds.split("/", 1) + [None])[:2] if "/" in creds else (creds, None)
                events.append(
                    _event(
                        timestamp=timestamp,
                        source_ip=source_ip,
                        source_port=source_port,
                        sensor_ip=sensor_ip,
                        username=username,
                        password=password,
                        event_type="accepted_login" if login["result"] == "succeeded" else "failed_login",
                        raw_line=line.rstrip("\n"),
                        log_type="kippo",
                    )
                )
                continue

            command = re.search(r"CMD: (?P<command>.*)$", message)
            if command:
                events.append(
                    _event(
                        timestamp=timestamp,
                        source_ip=source_ip,
                        source_port=source_port,
                        sensor_ip=sensor_ip,
                        command=command["command"],
                        event_type="command",
                        raw_line=line.rstrip("\n"),
                        log_type="kippo",
                    )
                )

    return events


def parse_ssh_logs(raw_root: Path) -> pd.DataFrame:
    events: list[dict] = []
    for path in sorted(raw_root.rglob("auth.log.anon")):
        events.extend(parse_auth_file(path))
    for path in sorted(raw_root.rglob("kippo.log.anon")):
        events.extend(parse_kippo_file(path))

    if not events:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "source_ip",
                "source_port",
                "sensor_ip",
                "event_type",
                "username",
                "password",
                "command",
                "is_suspicious_command",
                "raw_line",
                "log_type",
            ]
        )

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df.sort_values("timestamp").reset_index(drop=True)


def _count_event(series: pd.Series, names: Iterable[str]) -> int:
    names = set(names)
    return int(series.isin(names).sum())


def build_feature_table(events: pd.DataFrame, window: str = DEFAULT_WINDOW) -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame(columns=["source_ip", "window_start", *FEATURES, "pseudo_label", "pseudo_reason"])

    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["window_start"] = df["timestamp"].dt.floor(window)

    grouped = df.groupby(["source_ip", "window_start"], dropna=True)
    features = grouped.agg(
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        connection_count=("event_type", lambda s: _count_event(s, ["connection", "connection_scan", "connection_closed"])),
        failed_login_count=("event_type", lambda s: _count_event(s, ["failed_login", "failed_login_invalid"])),
        auth_failure_count=("event_type", lambda s: _count_event(s, ["auth_failure"])),
        invalid_user_count=("event_type", lambda s: _count_event(s, ["invalid_user", "failed_login_invalid"])),
        accepted_login_count=("event_type", lambda s: _count_event(s, ["accepted_login"])),
        command_count=("event_type", lambda s: _count_event(s, ["command"])),
        suspicious_command_count=("is_suspicious_command", "sum"),
        unique_users=("username", "nunique"),
        unique_passwords=("password", "nunique"),
        source_port_count=("source_port", "nunique"),
    ).reset_index()

    attempts = features["failed_login_count"] + features["accepted_login_count"]
    features["failure_rate"] = features["failed_login_count"] / attempts.clip(lower=1)
    features["invalid_user_rate"] = features["invalid_user_count"] / (
        features["failed_login_count"] + features["invalid_user_count"]
    ).clip(lower=1)
    features["commands_per_accepted"] = features["command_count"] / features["accepted_login_count"].clip(lower=1)
    features["success_after_fail"] = features["accepted_login_count"] / (
        features["failed_login_count"] + features["auth_failure_count"] + 1
    )
    active_minutes = ((features["last_seen"] - features["first_seen"]).dt.total_seconds() / 60.0).clip(lower=1)
    features["burst_score"] = (
        features["connection_count"] + features["failed_login_count"] + features["command_count"]
    ) / active_minutes

    features["pseudo_reason"] = features.apply(_pseudo_reason, axis=1)
    features["pseudo_label"] = (features["pseudo_reason"] != "low_activity").astype(int)
    return features[["source_ip", "window_start", "first_seen", "last_seen", *FEATURES, "pseudo_label", "pseudo_reason"]]


def _pseudo_reason(row: pd.Series) -> str:
    reasons: list[str] = []
    if row["failed_login_count"] >= 8:
        reasons.append("brute_force")
    if row["invalid_user_count"] >= 4 or row["unique_users"] >= 6:
        reasons.append("user_enumeration")
    if row["connection_count"] >= 12:
        reasons.append("connection_burst")
    if row["command_count"] >= 8:
        reasons.append("post_login_activity")
    if row["suspicious_command_count"] > 0:
        reasons.append("suspicious_command")
    if row["accepted_login_count"] > 0 and row["command_count"] > 0:
        reasons.append("honeypot_session")
    return "+".join(reasons) if reasons else "low_activity"

