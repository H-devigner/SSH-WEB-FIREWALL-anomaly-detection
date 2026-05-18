from __future__ import annotations

import argparse
import csv
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]

FIREWALL_LOG = ROOT / "Firewall" / "live_logs" / "firewall_live.csv"
WEB_LOG = ROOT / "WEB LOGS MODEL" / "live_logs" / "web_access.log"
SSH_LOG = ROOT / "SSH" / "live_logs" / "ssh_auth.log"

FIREWALL_COLUMNS = [
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


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def reset_outputs() -> None:
    for path in [
        FIREWALL_LOG,
        WEB_LOG,
        SSH_LOG,
        ROOT / "Firewall" / "live_scores" / "firewall_scores.jsonl",
        ROOT / "WEB LOGS MODEL" / "live_scores" / "web_scores.jsonl",
        ROOT / "SSH" / "live_scores" / "ssh_scores.jsonl",
    ]:
        if path.exists():
            path.unlink()


def load_firewall_samples() -> tuple[pd.DataFrame, pd.DataFrame]:
    source = pd.read_csv(ROOT / "Firewall" / "data" / "raw" / "firewall.csv")
    normal = source[source["Action"] == "allow"].reset_index(drop=True)
    anomaly = source[source["Action"] != "allow"].reset_index(drop=True)
    return normal, anomaly


def firewall_event(index: int, normal: pd.DataFrame, anomaly: pd.DataFrame) -> dict:
    source = anomaly if index % 4 == 3 else normal
    row = source.sample(1, random_state=random.randint(1, 10_000_000)).iloc[0]
    event = {name: row[name] for name in FIREWALL_COLUMNS}
    for name in FIREWALL_COLUMNS:
        if name != "Action":
            event[name] = int(event[name]) if name != "Elapsed Time (sec)" else float(event[name])
    return event


def write_firewall_event(event: dict) -> None:
    ensure_parent(FIREWALL_LOG)
    needs_header = not FIREWALL_LOG.exists() or FIREWALL_LOG.stat().st_size == 0
    with FIREWALL_LOG.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIREWALL_COLUMNS)
        if needs_header:
            writer.writeheader()
        writer.writerow(event)


def web_event(index: int) -> dict:
    attack = index % 4 == 3
    if attack:
        return {
            "host": "203.0.113.50",
            "method": random.choice(["GET", "POST"]),
            "url": random.choice(["/admin", "/wp-login.php", "/../../etc/passwd", "/api/upload"]),
            "status": random.choice([404, 404, 500]),
            "bytes": random.randint(60_000, 260_000),
        }
    return {
        "host": random.choice(["198.51.100.10", "198.51.100.22", "192.0.2.15"]),
        "method": "GET",
        "url": random.choice(["/", "/index.html", "/assets/app.js", "/health"]),
        "status": random.choice([200, 200, 200, 304]),
        "bytes": random.randint(300, 7_500),
    }


def apache_line(event: dict) -> str:
    stamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return (
        f'{event["host"]} - - [{stamp}] "{event["method"]} {event["url"]} HTTP/1.1" '
        f'{event["status"]} {event["bytes"]}'
    )


def write_web_event(event: dict) -> None:
    ensure_parent(WEB_LOG)
    with WEB_LOG.open("a") as handle:
        handle.write(apache_line(event) + "\n")


def ssh_line(index: int) -> str:
    sensor = "ssh-sensor-01"
    pid = 30_000 + index
    stamp = datetime.now().strftime("%b %e %H:%M:%S")
    if index % 4 == 3:
        source_ip = "203.0.113.90"
        user = random.choice(["root", "admin", "oracle", "deploy", "test"])
        port = random.randint(30_000, 61_000)
        return f"{stamp} {sensor} sshd[{pid}]: Failed password for invalid user {user} from {source_ip} port {port} ssh2"

    source_ip = random.choice(["198.51.100.24", "198.51.100.25"])
    user = random.choice(["ops", "backup", "deploy"])
    port = random.randint(30_000, 61_000)
    return f"{stamp} {sensor} sshd[{pid}]: Accepted publickey for {user} from {source_ip} port {port} ssh2"


def write_ssh_line(line: str) -> None:
    ensure_parent(SSH_LOG)
    with SSH_LOG.open("a") as handle:
        handle.write(line + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Firewall, Web, and SSH logs for live scoring.")
    parser.add_argument("--count", type=int, default=30, help="Number of events per type to generate.")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between generated event batches.")
    parser.add_argument("--reset", action="store_true", help="Remove existing live logs and score files first.")
    args = parser.parse_args()

    if args.reset:
        reset_outputs()

    normal_firewall, anomaly_firewall = load_firewall_samples()
    for index in range(args.count):
        write_firewall_event(firewall_event(index, normal_firewall, anomaly_firewall))
        write_web_event(web_event(index))
        write_ssh_line(ssh_line(index))
        print(f"generated batch {index + 1}/{args.count}", flush=True)
        if args.interval > 0:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
