from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score

from ssh_features import FEATURES


ROOT = Path(__file__).resolve().parents[1]
FEATURES_CSV = ROOT / "data" / "processed" / "ssh_features.csv"
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    model = joblib.load(MODELS_DIR / "ssh_isolation.pkl")
    pipeline = joblib.load(MODELS_DIR / "ssh_scaler.pkl")
    scaler = pipeline["scaler"]
    X_test_normal = pipeline["X_test_normal"]

    df = pd.read_csv(FEATURES_CSV)
    anomalies = df[df["pseudo_label"] == 1].copy()
    X_anomalies = scaler.transform(anomalies[FEATURES].fillna(0))

    X_eval = np.vstack([X_test_normal, X_anomalies])
    y_true = np.array([1] * len(X_test_normal) + [-1] * len(X_anomalies))
    y_binary = (y_true == -1).astype(int)

    y_pred = model.predict(X_eval)
    anomaly_scores = -model.decision_function(X_eval)

    report = classification_report(
        y_true,
        y_pred,
        target_names=["Anomaly", "Normal"],
        labels=[-1, 1],
        zero_division=0,
        output_dict=True,
    )
    print("=== SSH Classification Report (pseudo labels) ===")
    print(classification_report(y_true, y_pred, target_names=["Anomaly", "Normal"], labels=[-1, 1], zero_division=0))
    roc_auc = roc_auc_score(y_binary, anomaly_scores)
    print(f"ROC-AUC: {roc_auc:.4f}")

    normal_meta = pd.DataFrame(
        {
            "source_ip": "held_out_normal",
            "window_start": pd.NaT,
            "pseudo_label": 0,
            "pseudo_reason": "held_out_low_activity",
        },
        index=range(len(X_test_normal)),
    )
    anomaly_meta = anomalies[["source_ip", "window_start", "pseudo_label", "pseudo_reason"]].reset_index(drop=True)
    results = pd.concat([normal_meta, anomaly_meta], ignore_index=True)
    results["true_label"] = y_true
    results["prediction"] = y_pred
    results["anomaly_score"] = anomaly_scores
    results["is_anomaly"] = y_pred == -1
    results.to_csv(RESULTS_DIR / "ssh_evaluation.csv", index=False)
    with (RESULTS_DIR / "ssh_metrics.json").open("w") as handle:
        json.dump(
            {
                "normal_test_windows": int(len(X_test_normal)),
                "pseudo_anomaly_windows": int(len(X_anomalies)),
                "roc_auc": float(roc_auc),
                "classification_report": report,
            },
            handle,
            indent=2,
        )

    print("Saved results/ssh_evaluation.csv")
    print("Saved results/ssh_metrics.json")


if __name__ == "__main__":
    main()
