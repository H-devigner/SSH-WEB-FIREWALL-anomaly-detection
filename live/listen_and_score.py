from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
FIREWALL_ROOT = ROOT / "Firewall"
WEB_ROOT = ROOT / "WEB LOGS MODEL"
SSH_ROOT = ROOT / "SSH"

sys.path.insert(0, str(FIREWALL_ROOT / "src"))
sys.path.insert(0, str(SSH_ROOT / "src"))

from firewall_features import FEATURES as FIREWALL_FEATURES  # noqa: E402
from firewall_features import add_firewall_features  # noqa: E402
from ssh_features import FEATURES as SSH_FEATURES  # noqa: E402
from ssh_features import build_feature_table, parse_auth_line  # noqa: E402


FIREWALL_LOG = FIREWALL_ROOT / "live_logs" / "firewall_live.csv"
WEB_LOG = WEB_ROOT / "live_logs" / "web_access.log"
SSH_LOG = SSH_ROOT / "live_logs" / "ssh_auth.log"

FIREWALL_SCORE_FILE = FIREWALL_ROOT / "live_scores" / "firewall_scores.jsonl"
WEB_SCORE_FILE = WEB_ROOT / "live_scores" / "web_scores.jsonl"
SSH_SCORE_FILE = SSH_ROOT / "live_scores" / "ssh_scores.jsonl"

WEB_FEATURES = [
    "request_count",
    "unique_urls",
    "avg_bytes",
    "total_bytes",
    "error_rate",
    "status_404",
    "status_500",
    "post_rate",
    "url_diversity",
    "bytes_per_req",
    "error_to_ok_ratio",
    "max_bytes",
    "large_req_count",
]

WEB_PATTERN = re.compile(
    r"(?P<host>\S+) - - \[(?P<time>[^\]]+)\] "
    r"\"(?P<method>\S+) (?P<url>\S+) \S+\" (?P<status>\d{3}) (?P<bytes>\S+)"
)


class TailCursor:
    def __init__(self, path: Path, from_start: bool = False):
        self.path = path
        self.offset = 0
        if path.exists() and not from_start:
            self.offset = path.stat().st_size

    def read_new_lines(self) -> list[str]:
        if not self.path.exists():
            return []

        size = self.path.stat().st_size
        if size < self.offset:
            self.offset = 0

        with self.path.open("r", errors="ignore", newline="") as handle:
            handle.seek(self.offset)
            lines = handle.readlines()
            self.offset = handle.tell()
        return lines


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def append_score(path: Path, payload: dict) -> None:
    ensure_parent(path)
    with path.open("a") as handle:
        handle.write(json.dumps(payload, default=str) + "\n")


def risk_from_anomaly_score(score: float) -> float:
    return float(1.0 / (1.0 + math.exp(-score)))


def web_status_label(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "success"
    if 300 <= status_code < 400:
        return "redirect"
    if 400 <= status_code < 500:
        return "client_error"
    if 500 <= status_code < 600:
        return "server_error"
    return "other"


def ssh_status_label(event_type: str) -> str:
    if event_type == "accepted_login":
        return "accepted"
    if event_type == "failed_login":
        return "failed"
    if event_type in {"failed_login_invalid", "invalid_user"}:
        return "invalid_user"
    if event_type == "auth_failure":
        return "auth_failure"
    if event_type in {"connection", "connection_scan", "connection_closed"}:
        return "connection"
    if event_type == "command":
        return "command"
    return "other"


def score_frame(model, scaler, frame: pd.DataFrame, features: list[str], use_feature_names: bool = True) -> tuple[int, float]:
    feature_frame = frame[features].fillna(0)
    if use_feature_names:
        scaled = scaler.transform(feature_frame)
    else:
        scaled = scaler.transform(feature_frame.to_numpy(dtype=float))
    prediction = int(model.predict(scaled)[0])
    anomaly_score = float(-model.decision_function(scaled)[0])
    return prediction, anomaly_score


def load_firewall_model():
    model = joblib.load(FIREWALL_ROOT / "models" / "firewall_isolation.pkl")
    pipeline = joblib.load(FIREWALL_ROOT / "models" / "firewall_scaler_test.pkl")
    return model, pipeline["scaler"]


def firewall_row_from_line(line: str, header: list[str]) -> dict | None:
    if not line.strip() or line.startswith("Source Port,"):
        return None
    reader = csv.DictReader([",".join(header), line])
    try:
        row = next(reader)
    except StopIteration:
        return None

    numeric_fields = [name for name in header if name != "Action"]
    for name in numeric_fields:
        row[name] = float(row[name])
    return row


def make_firewall_handler() -> Callable[[str], dict | None]:
    model, scaler = load_firewall_model()
    header = [
        "Source Port",
        "Destination Port",
        "NAT Source Port",
        "NAT Destination Port",
        "Action",
        "Bytes",
        "Bytes Sent",
        "Bytes Received",
        "Packets",
        "Elapsed Time (sec)",
        "pkts_sent",
        "pkts_received",
    ]

    def handle(line: str) -> dict | None:
        row = firewall_row_from_line(line, header)
        if row is None:
            return None

        featured = add_firewall_features(pd.DataFrame([row]))
        prediction, anomaly_score = score_frame(model, scaler, featured, FIREWALL_FEATURES)
        return {
            "model": "firewall",
            "scored_at": datetime.now(timezone.utc).isoformat(),
            "action": row["Action"],
            "source_port": int(row["Source Port"]),
            "destination_port": int(row["Destination Port"]),
            "prediction": prediction,
            "is_anomaly": prediction == -1,
            "anomaly_score": anomaly_score,
            "risk_score": risk_from_anomaly_score(anomaly_score),
        }

    return handle


def parse_web_line(line: str) -> dict | None:
    match = WEB_PATTERN.match(line.strip())
    if not match:
        return None
    bytes_value = 0 if match["bytes"] == "-" else int(match["bytes"])
    timestamp = datetime.strptime(match["time"], "%d/%b/%Y:%H:%M:%S %z")
    return {
        "host": match["host"],
        "time": timestamp,
        "hour": timestamp.replace(minute=0, second=0, microsecond=0),
        "method": match["method"],
        "url": match["url"],
        "status": int(match["status"]),
        "status_label": web_status_label(int(match["status"])),
        "bytes": bytes_value,
    }


def web_features(events: list[dict]) -> pd.DataFrame:
    request_count = len(events)
    unique_urls = len({event["url"] for event in events})
    total_bytes = sum(event["bytes"] for event in events)
    status_404 = sum(event["status"] == 404 for event in events)
    status_500 = sum(event["status"] == 500 for event in events)
    status_200 = sum(event["status"] == 200 for event in events)
    post_count = sum(event["method"] == "POST" for event in events)
    values = {
        "request_count": request_count,
        "unique_urls": unique_urls,
        "avg_bytes": total_bytes / max(request_count, 1),
        "total_bytes": total_bytes,
        "error_rate": sum(event["status"] >= 400 for event in events) / max(request_count, 1),
        "status_404": status_404,
        "status_500": status_500,
        "post_rate": post_count / max(request_count, 1),
        "url_diversity": unique_urls / max(request_count, 1),
        "bytes_per_req": total_bytes / max(request_count, 1),
        "error_to_ok_ratio": status_404 / max(status_200, 1),
        "max_bytes": max((event["bytes"] for event in events), default=0),
        "large_req_count": sum(event["bytes"] > 50_000 for event in events),
    }
    return pd.DataFrame([values])


def make_web_handler() -> Callable[[str], dict | None]:
    model = joblib.load(WEB_ROOT / "models" / "anomaly_model.pkl")
    scaler = joblib.load(WEB_ROOT / "models" / "scaler.pkl")
    windows: dict[tuple[str, datetime], list[dict]] = defaultdict(list)

    def handle(line: str) -> dict | None:
        event = parse_web_line(line)
        if event is None:
            return None

        key = (event["host"], event["hour"])
        windows[key].append(event)
        featured = web_features(windows[key])
        prediction, anomaly_score = score_frame(model, scaler, featured, WEB_FEATURES, use_feature_names=False)
        return {
            "model": "web",
            "scored_at": datetime.now(timezone.utc).isoformat(),
            "host": event["host"],
            "url": event["url"],
            "status": event["status"],
            "http_status": event["status"],
            "status_label": event["status_label"],
            "window_events": len(windows[key]),
            "prediction": prediction,
            "is_anomaly": prediction == -1,
            "anomaly_score": anomaly_score,
            "risk_score": risk_from_anomaly_score(anomaly_score),
        }

    return handle


def make_ssh_handler() -> Callable[[str], dict | None]:
    model = joblib.load(SSH_ROOT / "models" / "ssh_isolation.pkl")
    pipeline = joblib.load(SSH_ROOT / "models" / "ssh_scaler.pkl")
    scaler = pipeline["scaler"]
    windows: dict[tuple[str, pd.Timestamp], list[dict]] = defaultdict(list)

    def handle(line: str) -> dict | None:
        event = parse_auth_line(line)
        if event is None:
            return None

        timestamp = pd.to_datetime(event["timestamp"])
        window_start = timestamp.floor("10min")
        key = (event["source_ip"], window_start)
        windows[key].append(event)
        featured = build_feature_table(pd.DataFrame(windows[key]))
        prediction, anomaly_score = score_frame(model, scaler, featured, SSH_FEATURES)
        return {
            "model": "ssh",
            "scored_at": datetime.now(timezone.utc).isoformat(),
            "source_ip": event["source_ip"],
            "event_type": event["event_type"],
            "status_label": ssh_status_label(event["event_type"]),
            "window_events": len(windows[key]),
            "prediction": prediction,
            "is_anomaly": prediction == -1,
            "anomaly_score": anomaly_score,
            "risk_score": risk_from_anomaly_score(anomaly_score),
        }

    return handle


def main() -> None:
    parser = argparse.ArgumentParser(description="Tail live log files and score them with trained models.")
    parser.add_argument("--poll-interval", type=float, default=0.25, help="Seconds between file polls.")
    parser.add_argument("--max-events", type=int, default=0, help="Stop after scoring this many events; 0 means run forever.")
    parser.add_argument("--from-start", action="store_true", help="Consume existing file contents before tailing new data.")
    args = parser.parse_args()

    listeners = [
        {
            "name": "firewall",
            "cursor": TailCursor(FIREWALL_LOG, from_start=args.from_start),
            "handler": make_firewall_handler(),
            "score_file": FIREWALL_SCORE_FILE,
        },
        {
            "name": "web",
            "cursor": TailCursor(WEB_LOG, from_start=args.from_start),
            "handler": make_web_handler(),
            "score_file": WEB_SCORE_FILE,
        },
        {
            "name": "ssh",
            "cursor": TailCursor(SSH_LOG, from_start=args.from_start),
            "handler": make_ssh_handler(),
            "score_file": SSH_SCORE_FILE,
        },
    ]

    scored = 0
    print("listening for Firewall, Web, and SSH logs...", flush=True)
    while True:
        made_progress = False
        for listener in listeners:
            for line in listener["cursor"].read_new_lines():
                result = listener["handler"](line)
                if result is None:
                    continue
                append_score(listener["score_file"], result)
                print(json.dumps(result), flush=True)
                scored += 1
                made_progress = True
                if args.max_events and scored >= args.max_events:
                    return

        if not made_progress:
            time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
