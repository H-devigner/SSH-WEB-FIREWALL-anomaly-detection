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

WEB_NORMAL_HOSTS = [
    "198.51.100.10",
    "198.51.100.22",
    "198.51.100.31",
    "198.51.100.44",
    "192.0.2.15",
    "192.0.2.28",
    "192.0.2.61",
    "203.0.113.12",
]
WEB_SUSPICIOUS_HOSTS = [
    "203.0.113.50",
    "203.0.113.77",
    "203.0.113.88",
    "198.51.100.190",
    "192.0.2.200",
]
WEB_NORMAL_URLS = [
    "/",
    "/index.html",
    "/health",
    "/assets/app.js",
    "/assets/theme.css",
    "/images/logo.png",
    "/api/products",
    "/api/orders",
    "/docs/api",
    "/login",
    "/search?q=firewall",
]
WEB_SUSPICIOUS_URLS = [
    "/admin",
    "/wp-login.php",
    "/../../etc/passwd",
    "/.env",
    "/phpmyadmin/index.php",
    "/api/upload",
    "/cgi-bin/test.cgi",
    "/shell?cmd=id",
    "/manager/html",
    "/login?redirect=../../etc/passwd",
]

SSH_SENSORS = ["ssh-sensor-01", "ssh-sensor-02", "edge-bastion-01", "vpn-gateway-01"]
SSH_NORMAL_HOSTS = [
    "198.51.100.24",
    "198.51.100.25",
    "198.51.100.36",
    "192.0.2.41",
    "192.0.2.42",
    "203.0.113.21",
]
SSH_SUSPICIOUS_HOSTS = [
    "203.0.113.90",
    "203.0.113.91",
    "203.0.113.92",
    "198.51.100.201",
    "192.0.2.222",
]
SSH_NORMAL_USERS = ["ops", "backup", "deploy", "git", "monitor", "service"]
SSH_SUSPICIOUS_USERS = ["root", "admin", "oracle", "test", "postgres", "ubuntu", "guest", "support"]


def is_suspicious_event(attack_rate: float) -> bool:
    return random.random() < max(0.0, min(attack_rate, 1.0))


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
        ensure_parent(path)
        path.write_text("")


def load_firewall_samples() -> tuple[pd.DataFrame, pd.DataFrame]:
    source = pd.read_csv(ROOT / "Firewall" / "data" / "raw" / "firewall.csv")
    normal = source[source["Action"] == "allow"].reset_index(drop=True)
    anomaly = source[source["Action"] != "allow"].reset_index(drop=True)
    return normal, anomaly


def firewall_event(normal: pd.DataFrame, anomaly: pd.DataFrame, attack_rate: float) -> dict:
    source = anomaly if is_suspicious_event(attack_rate) else normal
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


def web_event(attack_rate: float) -> dict:
    attack = is_suspicious_event(attack_rate)
    if attack:
        mode = random.choice(["scanner", "bruteforce", "upload_probe", "path_traversal"])
        status_pool = {
            "scanner": [400, 401, 403, 404, 404, 429],
            "bruteforce": [401, 401, 403, 429, 500],
            "upload_probe": [403, 404, 413, 500, 502, 503],
            "path_traversal": [400, 403, 404, 500],
        }[mode]
        return {
            "host": random.choice(WEB_SUSPICIOUS_HOSTS),
            "method": random.choice(["GET", "POST", "PUT", "DELETE"]),
            "url": random.choice(WEB_SUSPICIOUS_URLS),
            "status": random.choice(status_pool),
            "bytes": random.randint(60_000, 260_000),
        }
    return {
        "host": random.choice(WEB_NORMAL_HOSTS),
        "method": random.choices(["GET", "HEAD", "POST"], weights=[0.78, 0.12, 0.10], k=1)[0],
        "url": random.choice(WEB_NORMAL_URLS),
        "status": random.choices([200, 201, 204, 206, 301, 302, 304, 401], weights=[58, 3, 5, 2, 5, 4, 20, 3], k=1)[0],
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


def ssh_line(index: int, attack_rate: float) -> str:
    sensor = random.choice(SSH_SENSORS)
    pid = 30_000 + index + random.randint(0, 2_500)
    stamp = datetime.now().strftime("%b %e %H:%M:%S")
    if is_suspicious_event(attack_rate):
        source_ip = random.choice(SSH_SUSPICIOUS_HOSTS)
        user = random.choice(SSH_SUSPICIOUS_USERS)
        port = random.randint(30_000, 61_000)
        event_type = random.choices(
            [
                "failed_invalid",
                "failed_known",
                "invalid_user",
                "auth_failure",
                "connection_scan",
                "connection_closed",
            ],
            weights=[38, 18, 18, 10, 10, 6],
            k=1,
        )[0]
        if event_type == "failed_invalid":
            return f"{stamp} {sensor} sshd[{pid}]: Failed password for invalid user {user} from {source_ip} port {port} ssh2"
        if event_type == "failed_known":
            return f"{stamp} {sensor} sshd[{pid}]: Failed password for {user} from {source_ip} port {port} ssh2"
        if event_type == "invalid_user":
            return f"{stamp} {sensor} sshd[{pid}]: Invalid user {user} from {source_ip}"
        if event_type == "auth_failure":
            return (
                f"{stamp} {sensor} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; "
                f"logname= uid=0 euid=0 tty=ssh ruser= rhost={source_ip} user={user}"
            )
        if event_type == "connection_scan":
            return f"{stamp} {sensor} sshd[{pid}]: Did not receive identification string from {source_ip}"
        return f"{stamp} {sensor} sshd[{pid}]: Connection closed by {source_ip} port {port} [preauth]"

    source_ip = random.choice(SSH_NORMAL_HOSTS)
    user = random.choice(SSH_NORMAL_USERS)
    port = random.randint(30_000, 61_000)
    auth_method = random.choice(["publickey", "password"])
    return f"{stamp} {sensor} sshd[{pid}]: Accepted {auth_method} for {user} from {source_ip} port {port} ssh2"


def write_ssh_line(line: str) -> None:
    ensure_parent(SSH_LOG)
    with SSH_LOG.open("a") as handle:
        handle.write(line + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Firewall, Web, and SSH logs for live scoring.")
    parser.add_argument("--count", type=int, default=30, help="Number of events per type to generate.")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between generated event batches.")
    parser.add_argument("--attack-rate", type=float, default=0.30, help="Approximate suspicious event ratio per log type.")
    parser.add_argument("--seed", type=int, default=None, help="Optional random seed for reproducible demo logs.")
    parser.add_argument("--reset", action="store_true", help="Remove existing live logs and score files first.")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.reset:
        reset_outputs()

    normal_firewall, anomaly_firewall = load_firewall_samples()
    for index in range(args.count):
        write_firewall_event(firewall_event(normal_firewall, anomaly_firewall, args.attack_rate))
        write_web_event(web_event(args.attack_rate))
        write_ssh_line(ssh_line(index, args.attack_rate))
        print(f"generated batch {index + 1}/{args.count}", flush=True)
        if args.interval > 0:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
