from __future__ import annotations

import json
import os
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    auc,
    classification_report,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)


ROOT = Path(__file__).resolve().parents[1]
MPL_CACHE = ROOT / ".cache" / "matplotlib"
MPL_CACHE.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPL_CACHE))
import matplotlib  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

FIREWALL_ROOT = ROOT / "Firewall"
SSH_ROOT = ROOT / "SSH"
WEB_ROOT = ROOT / "WEB LOGS MODEL"
WEB_RESULTS_DIR = WEB_ROOT / "results"
WEB_MODELS_DIR = WEB_ROOT / "models"

sys.path.insert(0, str(FIREWALL_ROOT / "src"))
sys.path.insert(0, str(SSH_ROOT / "src"))

from firewall_features import FEATURES as FIREWALL_FEATURES  # noqa: E402
from firewall_features import add_firewall_features, load_firewall_data  # noqa: E402
from ssh_features import FEATURES as SSH_FEATURES  # noqa: E402


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

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.utils.validation")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def save_json(path: Path, data: dict) -> None:
    with path.open("w") as handle:
        json.dump(data, handle, indent=2)


def normalized_labels(values: pd.Series | np.ndarray) -> np.ndarray:
    values = np.asarray(values)
    return (values == -1).astype(int)


def plot_confusion(y_true: np.ndarray, y_pred: np.ndarray, path: Path, title: str) -> None:
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fig, ax = plt.subplots(figsize=(5.5, 4.8))
    image = ax.imshow(matrix, cmap="Blues")
    ax.set_title(title)
    ax.set_xticks([0, 1], labels=["Normal", "Anomaly"])
    ax.set_yticks([0, 1], labels=["Normal", "Anomaly"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")

    for row in range(matrix.shape[0]):
        for col in range(matrix.shape[1]):
            value = matrix[row, col]
            ax.text(col, row, f"{value:,}", ha="center", va="center", color="black")

    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_roc(y_true: np.ndarray, scores: np.ndarray, path: Path, title: str) -> float:
    fpr, tpr, _ = roc_curve(y_true, scores)
    roc_auc = auc(fpr, tpr)
    fig, ax = plt.subplots(figsize=(6, 4.8))
    ax.plot(fpr, tpr, label=f"ROC AUC = {roc_auc:.4f}", color="#2563eb", linewidth=2)
    ax.plot([0, 1], [0, 1], linestyle="--", color="#6b7280", linewidth=1)
    ax.set_title(title)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.legend(loc="lower right")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return float(roc_auc)


def plot_precision_recall(y_true: np.ndarray, scores: np.ndarray, path: Path, title: str) -> float:
    precision, recall, _ = precision_recall_curve(y_true, scores)
    pr_auc = auc(recall, precision)
    fig, ax = plt.subplots(figsize=(6, 4.8))
    ax.plot(recall, precision, label=f"PR AUC = {pr_auc:.4f}", color="#0f766e", linewidth=2)
    ax.set_title(title)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.legend(loc="lower left")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    return float(pr_auc)


def plot_score_distribution(
    y_true: np.ndarray,
    scores: np.ndarray,
    path: Path,
    title: str,
    label_note: str,
) -> None:
    fig, ax = plt.subplots(figsize=(7, 4.8))
    ax.hist(scores[y_true == 0], bins=45, alpha=0.72, label="Normal", color="#64748b")
    ax.hist(scores[y_true == 1], bins=45, alpha=0.72, label="Anomaly", color="#dc2626")
    ax.set_title(title)
    ax.set_xlabel("Anomaly score, higher means more anomalous")
    ax.set_ylabel("Windows")
    ax.legend(title=label_note)
    ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_label_balance(y_true: np.ndarray, path: Path, title: str, label_note: str) -> None:
    counts = np.array([(y_true == 0).sum(), (y_true == 1).sum()])
    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    bars = ax.bar(["Normal", "Anomaly"], counts, color=["#64748b", "#dc2626"])
    ax.set_title(title)
    ax.set_ylabel("Rows/windows")
    ax.set_xlabel(label_note)
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width() / 2, height, f"{int(height):,}", ha="center", va="bottom")
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def feature_score_correlations(features: pd.DataFrame, scores: np.ndarray, feature_cols: list[str]) -> pd.DataFrame:
    rows = []
    score_values = np.asarray(scores, dtype=float)
    for name in feature_cols:
        values = pd.to_numeric(features[name], errors="coerce").fillna(0).to_numpy(dtype=float)
        if np.std(values) == 0 or np.std(score_values) == 0:
            corr = 0.0
        else:
            corr = float(np.corrcoef(values, score_values)[0, 1])
        rows.append({"feature": name, "correlation": corr, "abs_correlation": abs(corr)})
    return pd.DataFrame(rows).sort_values("abs_correlation", ascending=False)


def plot_feature_correlations(correlations: pd.DataFrame, path: Path, title: str) -> None:
    top = correlations.head(10).sort_values("abs_correlation")
    fig, ax = plt.subplots(figsize=(7, 5.4))
    colors = ["#dc2626" if value >= 0 else "#2563eb" for value in top["correlation"]]
    ax.barh(top["feature"], top["correlation"], color=colors)
    ax.axvline(0, color="#111827", linewidth=0.9)
    ax.set_title(title)
    ax.set_xlabel("Pearson correlation with anomaly score")
    ax.grid(axis="x", alpha=0.2)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def benchmark_inference(
    model,
    scaler,
    raw_features: pd.DataFrame,
    feature_cols: list[str],
    batch_sizes: list[int],
    repeats: int = 5,
) -> pd.DataFrame:
    rows = []
    source = raw_features[feature_cols].fillna(0).reset_index(drop=True)
    if len(source) == 0:
        return pd.DataFrame(columns=["batch_size", "avg_ms", "ms_per_sample", "samples_per_second"])

    for batch_size in batch_sizes:
        take = min(batch_size, len(source))
        batch = source.iloc[:take]

        transform_with_scaler(scaler, batch)
        durations = []
        for _ in range(repeats):
            start = time.perf_counter()
            scaled = transform_with_scaler(scaler, batch)
            model.predict(scaled)
            model.decision_function(scaled)
            durations.append(time.perf_counter() - start)

        avg_seconds = float(np.mean(durations))
        rows.append(
            {
                "batch_size": int(take),
                "avg_ms": avg_seconds * 1000,
                "ms_per_sample": (avg_seconds / take) * 1000,
                "samples_per_second": take / avg_seconds if avg_seconds else 0.0,
            }
        )

    return pd.DataFrame(rows)


def plot_inference_benchmark(bench: pd.DataFrame, path: Path, title: str) -> None:
    fig, ax = plt.subplots(figsize=(6.5, 4.8))
    ax.plot(bench["batch_size"], bench["ms_per_sample"], marker="o", color="#7c3aed", linewidth=2)
    ax.set_title(title)
    ax.set_xlabel("Batch size")
    ax.set_ylabel("Milliseconds per sample")
    ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def transform_with_scaler(scaler, feature_frame: pd.DataFrame) -> np.ndarray:
    if hasattr(scaler, "feature_names_in_"):
        return scaler.transform(feature_frame)
    return scaler.transform(feature_frame.to_numpy(dtype=float))


def evaluate_labeled_model(
    *,
    name: str,
    out_dir: Path,
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray,
    label_note: str,
    raw_features: pd.DataFrame,
    feature_cols: list[str],
    model,
    scaler,
) -> dict:
    ensure_dir(out_dir)
    figures_dir = out_dir / "figures"
    ensure_dir(figures_dir)

    validation_title = f"{name} Validation"

    roc_auc = plot_roc(y_true, scores, figures_dir / "roc_curve.png", f"{validation_title} ROC Curve")
    pr_auc = plot_precision_recall(
        y_true,
        scores,
        figures_dir / "precision_recall_curve.png",
        f"{validation_title} Precision-Recall Curve",
    )
    plot_confusion(y_true, y_pred, figures_dir / "confusion_matrix.png", f"{validation_title} Confusion Matrix")
    plot_score_distribution(
        y_true,
        scores,
        figures_dir / "score_distribution.png",
        f"{validation_title} Score Distribution",
        label_note,
    )
    plot_label_balance(y_true, figures_dir / "label_balance.png", f"{validation_title} Label Balance", label_note)

    correlations = feature_score_correlations(raw_features, scores_for_rows(raw_features, model, scaler, feature_cols), feature_cols)
    correlations.to_csv(out_dir / "feature_score_correlations.csv", index=False)
    plot_feature_correlations(
        correlations,
        figures_dir / "feature_score_correlation.png",
        f"{validation_title} Feature/Score Correlation",
    )

    bench = benchmark_inference(model, scaler, raw_features, feature_cols, batch_sizes=[1, 16, 64, 256, 1024])
    bench.to_csv(out_dir / "inference_benchmark.csv", index=False)
    plot_inference_benchmark(bench, figures_dir / "inference_latency.png", f"{validation_title} Inference Latency")

    report = classification_report(
        y_true,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Anomaly"],
        zero_division=0,
        output_dict=True,
    )
    summary = {
        "model": name,
        "label_note": label_note,
        "rows": int(len(y_true)),
        "normal_rows": int((y_true == 0).sum()),
        "anomaly_rows": int((y_true == 1).sum()),
        "predicted_anomalies": int((y_pred == 1).sum()),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "classification_report": report,
        "inference_ms_per_sample_batch_1": float(bench.iloc[0]["ms_per_sample"]) if not bench.empty else None,
        "inference_samples_per_second_batch_1024": float(bench.iloc[-1]["samples_per_second"]) if not bench.empty else None,
    }
    save_json(out_dir / "performance_summary.json", summary)
    return summary


def scores_for_rows(raw_features: pd.DataFrame, model, scaler, feature_cols: list[str]) -> np.ndarray:
    x = raw_features[feature_cols].fillna(0)
    return -model.decision_function(transform_with_scaler(scaler, x))


def evaluate_firewall() -> dict:
    results = pd.read_csv(FIREWALL_ROOT / "results" / "firewall_evaluation.csv")
    y_true = normalized_labels(results["true_label"])
    y_pred = normalized_labels(results["prediction"])
    scores = results["anomaly_score"].to_numpy(dtype=float)

    model = joblib.load(FIREWALL_ROOT / "models" / "firewall_isolation.pkl")
    pipeline = joblib.load(FIREWALL_ROOT / "models" / "firewall_scaler_test.pkl")
    scaler = pipeline["scaler"]

    raw = add_firewall_features(load_firewall_data(FIREWALL_ROOT / "data" / "raw" / "firewall.csv"))
    return evaluate_labeled_model(
        name="Firewall",
        out_dir=FIREWALL_ROOT / "results",
        y_true=y_true,
        y_pred=y_pred,
        scores=scores,
        label_note="Ground truth from Action field",
        raw_features=raw,
        feature_cols=FIREWALL_FEATURES,
        model=model,
        scaler=scaler,
    )


def evaluate_ssh() -> dict:
    results = pd.read_csv(SSH_ROOT / "results" / "ssh_evaluation.csv")
    y_true = normalized_labels(results["true_label"])
    y_pred = normalized_labels(results["prediction"])
    scores = results["anomaly_score"].to_numpy(dtype=float)

    model = joblib.load(SSH_ROOT / "models" / "ssh_isolation.pkl")
    pipeline = joblib.load(SSH_ROOT / "models" / "ssh_scaler.pkl")
    scaler = pipeline["scaler"]

    raw = pd.read_csv(SSH_ROOT / "data" / "processed" / "ssh_features.csv")
    return evaluate_labeled_model(
        name="SSH",
        out_dir=SSH_ROOT / "results",
        y_true=y_true,
        y_pred=y_pred,
        scores=scores,
        label_note="Pseudo labels from SSH behavior rules",
        raw_features=raw,
        feature_cols=SSH_FEATURES,
        model=model,
        scaler=scaler,
    )


def evaluate_web() -> dict:
    results = pd.read_csv(WEB_RESULTS_DIR / "web_evaluation.csv")
    y_true = (results["error_rate"] > 0.5).astype(int).to_numpy()
    y_pred = (results["is_anomaly"] == -1).astype(int).to_numpy()
    scores = -results["anomaly_score"].to_numpy(dtype=float)

    model = joblib.load(WEB_MODELS_DIR / "anomaly_model.pkl")
    scaler = joblib.load(WEB_MODELS_DIR / "scaler.pkl")

    return evaluate_labeled_model(
        name="Web",
        out_dir=WEB_RESULTS_DIR,
        y_true=y_true,
        y_pred=y_pred,
        scores=scores,
        label_note="Pseudo labels from error_rate > 0.5",
        raw_features=results,
        feature_cols=WEB_FEATURES,
        model=model,
        scaler=scaler,
    )


def main() -> None:
    print("Evaluating Firewall...", flush=True)
    firewall = evaluate_firewall()
    print("Evaluating SSH...", flush=True)
    ssh = evaluate_ssh()
    print("Evaluating Web...", flush=True)
    web = evaluate_web()
    summaries = [firewall, ssh, web]
    summary_rows = []
    for item in summaries:
        summary_rows.append(
            {
                "model": item["model"],
                "rows": item["rows"],
                "normal_rows": item["normal_rows"],
                "anomaly_rows": item["anomaly_rows"],
                "predicted_anomalies": item["predicted_anomalies"],
                "roc_auc": item["roc_auc"],
                "pr_auc": item["pr_auc"],
                "inference_ms_per_sample_batch_1": item["inference_ms_per_sample_batch_1"],
                "inference_samples_per_second_batch_1024": item["inference_samples_per_second_batch_1024"],
            }
        )

    summary = pd.DataFrame(summary_rows)
    summary.to_csv(ROOT / "evaluation" / "performance_summary.csv", index=False)
    save_json(ROOT / "evaluation" / "performance_summary.json", {"models": summaries})
    print(summary.to_string(index=False))


if __name__ == "__main__":
    main()
