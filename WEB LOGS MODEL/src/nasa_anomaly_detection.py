"""
NASA HTTP Log - Offline Anomaly Detection Pipeline
==================================================
Pipeline: download/decompress -> parse -> feature engineering ->
Isolation Forest training -> batch scoring -> CSV/metrics export.

Usage:
    python nasa_anomaly_detection.py
"""

from __future__ import annotations

import gzip
import json
import os
import re
import urllib.request
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[1]

LOG_URL = "ftp://ita.ee.lbl.gov/traces/NASA_access_log_Jul95.gz"
RAW_DIR = ROOT / "data" / "raw"
RESULTS_DIR = ROOT / "results"
MODELS_DIR = ROOT / "models"
LOG_GZ = RAW_DIR / "NASA_access_log_Jul95.gz"
LOG_FILE = RAW_DIR / "NASA_access_log_Jul95.txt"
RESULTS_CSV = RESULTS_DIR / "web_evaluation.csv"
FLAGGED_CSV = RESULTS_DIR / "flagged_anomalies.csv"
METRICS_JSON = RESULTS_DIR / "web_metrics.json"
MODEL_FILE = MODELS_DIR / "anomaly_model.pkl"
SCALER_FILE = MODELS_DIR / "scaler.pkl"

TIME_WINDOW = "1h"
CONTAMINATION = 0.05
N_ESTIMATORS = 200

FEATURE_COLS = [
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

LOG_PATTERN = re.compile(
    r"(?P<host>\S+)"
    r" - -"
    r" \[(?P<time>[^\]]+)\]"
    r" \"(?P<method>\S+)"
    r" (?P<url>\S+)"
    r" \S+\""
    r" (?P<status>\d{3})"
    r" (?P<bytes>\S+)"
)


def ensure_dataset() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    if LOG_FILE.exists():
        print(f"Log file already exists: {LOG_FILE.name}")
        return

    if not LOG_GZ.exists():
        print("Downloading NASA HTTP log dataset...")
        urllib.request.urlretrieve(LOG_URL, LOG_GZ)
        print(f"Downloaded: {LOG_GZ.name}")

    print("Decompressing NASA HTTP log...")
    with gzip.open(LOG_GZ, "rb") as source, LOG_FILE.open("wb") as target:
        target.write(source.read())
    print(f"Decompressed: {LOG_FILE.name}")


def parse_logs(filepath: Path) -> pd.DataFrame:
    print(f"Parsing log file: {filepath.name}")
    records: list[dict] = []
    skipped = 0

    with filepath.open("r", errors="ignore") as handle:
        for line in handle:
            match = LOG_PATTERN.match(line.strip())
            if not match:
                skipped += 1
                continue

            records.append(
                {
                    "host": match["host"],
                    "time": match["time"],
                    "method": match["method"],
                    "url": match["url"],
                    "status": int(match["status"]),
                    "bytes": 0 if match["bytes"] == "-" else int(match["bytes"]),
                }
            )

    df = pd.DataFrame(records)
    df["time"] = pd.to_datetime(df["time"], format="%d/%b/%Y:%H:%M:%S %z", utc=True)
    df["hour"] = df["time"].dt.floor(TIME_WINDOW)

    print(f"Parsed {len(df):,} entries; skipped {skipped:,} malformed lines")
    return df


def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    print("Engineering per-host hourly features...")
    grouped = df.groupby(["host", "hour"])
    features = grouped.agg(
        request_count=("url", "count"),
        unique_urls=("url", "nunique"),
        avg_bytes=("bytes", "mean"),
        total_bytes=("bytes", "sum"),
        error_rate=("status", lambda values: (values >= 400).mean()),
        status_404=("status", lambda values: (values == 404).sum()),
        status_500=("status", lambda values: (values == 500).sum()),
        status_200=("status", lambda values: (values == 200).sum()),
        post_rate=("method", lambda values: (values == "POST").mean()),
        get_rate=("method", lambda values: (values == "GET").mean()),
        max_bytes=("bytes", "max"),
        large_req_count=("bytes", lambda values: (values > 50000).sum()),
    ).reset_index()

    features["url_diversity"] = features["unique_urls"] / features["request_count"].clip(lower=1)
    features["bytes_per_req"] = features["total_bytes"] / features["request_count"].clip(lower=1)
    features["error_to_ok_ratio"] = features["status_404"] / features["status_200"].clip(lower=1)

    print(f"Feature table rows: {len(features):,}")
    return features


def train_model(features: pd.DataFrame):
    print(f"Training Isolation Forest (contamination={CONTAMINATION}, trees={N_ESTIMATORS})...")
    x = features[FEATURE_COLS].fillna(0).values

    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(x)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x_scaled)
    print("Model trained")
    return model, scaler, x_scaled


def score_and_export(features: pd.DataFrame, model, x_scaled) -> tuple[pd.DataFrame, pd.DataFrame]:
    print("Scoring all feature windows...")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    scored = features.copy()
    scored["anomaly_score"] = model.decision_function(x_scaled)
    scored["is_anomaly"] = model.predict(x_scaled)
    scored["label"] = scored["is_anomaly"].map({1: "normal", -1: "ANOMALY"})

    results = scored.sort_values("anomaly_score", ascending=True)
    flagged = results[results["is_anomaly"] == -1]

    results.to_csv(RESULTS_CSV, index=False)
    flagged.to_csv(FLAGGED_CSV, index=False)

    metrics = {
        "total_windows": int(len(results)),
        "flagged_windows": int(len(flagged)),
        "flagged_rate": float(len(flagged) / max(len(results), 1)),
        "score_min": float(results["anomaly_score"].min()),
        "score_max": float(results["anomaly_score"].max()),
        "score_mean": float(results["anomaly_score"].mean()),
        "score_std": float(results["anomaly_score"].std()),
        "contamination": CONTAMINATION,
        "n_estimators": N_ESTIMATORS,
        "features": FEATURE_COLS,
    }
    with METRICS_JSON.open("w") as handle:
        json.dump(metrics, handle, indent=2)

    print(f"Scored {len(results):,} windows")
    print(f"Flagged {len(flagged):,} anomalies ({metrics['flagged_rate'] * 100:.1f}%)")
    print(f"Saved {RESULTS_CSV.name}, {FLAGGED_CSV.name}, and {METRICS_JSON.name}")

    if not flagged.empty:
        print("\nTop 10 most anomalous host/hour windows:")
        cols = ["host", "hour", "request_count", "error_rate", "status_404", "unique_urls", "anomaly_score"]
        print(flagged[cols].head(10).to_string(index=False))

    return results, flagged


def save_model(model, scaler) -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_FILE)
    joblib.dump(scaler, SCALER_FILE)
    print(f"Saved {MODEL_FILE.name} and {SCALER_FILE.name}")


def main() -> None:
    print("=" * 55)
    print("NASA HTTP Log - Offline Anomaly Detection Pipeline")
    print("=" * 55)

    ensure_dataset()
    df = parse_logs(LOG_FILE)
    features = engineer_features(df)
    model, scaler, x_scaled = train_model(features)
    score_and_export(features, model, x_scaled)
    save_model(model, scaler)

    # Keep the repository small; the compressed source remains in place.
    if LOG_FILE.exists():
        os.remove(LOG_FILE)
        print(f"Removed temporary extracted log: {LOG_FILE.name}")


if __name__ == "__main__":
    main()
