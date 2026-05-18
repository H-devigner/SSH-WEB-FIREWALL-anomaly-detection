from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, roc_auc_score

from firewall_features import add_firewall_features, load_firewall_data


ROOT = Path(__file__).resolve().parents[1]
DATA_CSV = ROOT / "data" / "raw" / "firewall.csv"
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"


def main() -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    model = joblib.load(MODELS_DIR / "firewall_isolation.pkl")
    pipeline = joblib.load(MODELS_DIR / "firewall_scaler_test.pkl")
    scaler = pipeline["scaler"]
    features = pipeline["features"]
    x_test_normal = pipeline["X_test_normal"]

    df = add_firewall_features(load_firewall_data(DATA_CSV))
    anomalies = df[df["Action"] != "allow"][features].dropna()
    x_anomalies = scaler.transform(anomalies)

    x_eval = np.vstack([x_test_normal, x_anomalies])
    y_true = np.array([1] * len(x_test_normal) + [-1] * len(x_anomalies))
    y_binary = (y_true == -1).astype(int)

    y_pred = model.predict(x_eval)
    anomaly_scores = -model.decision_function(x_eval)
    roc_auc = roc_auc_score(y_binary, anomaly_scores)

    report = classification_report(
        y_true,
        y_pred,
        target_names=["Anomaly", "Normal"],
        labels=[-1, 1],
        zero_division=0,
        output_dict=True,
    )

    print("=== Firewall Classification Report ===")
    print(
        classification_report(
            y_true,
            y_pred,
            target_names=["Anomaly", "Normal"],
            labels=[-1, 1],
            zero_division=0,
        )
    )
    print(f"ROC-AUC: {roc_auc:.4f}")

    results = pd.DataFrame(x_eval, columns=features)
    results["true_label"] = y_true
    results["prediction"] = y_pred
    results["anomaly_score"] = anomaly_scores
    results["is_anomaly"] = y_pred == -1
    results.to_csv(RESULTS_DIR / "firewall_evaluation.csv", index=False)

    with (RESULTS_DIR / "firewall_metrics.json").open("w") as handle:
        json.dump(
            {
                "normal_test_rows": int(len(x_test_normal)),
                "anomaly_rows": int(len(x_anomalies)),
                "roc_auc": float(roc_auc),
                "classification_report": report,
            },
            handle,
            indent=2,
        )

    print("Saved results/firewall_evaluation.csv")
    print("Saved results/firewall_metrics.json")


if __name__ == "__main__":
    main()
