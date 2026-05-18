import joblib
import numpy as np
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

model  = joblib.load(ROOT / "models" / "anomaly_model.pkl")
scaler = joblib.load(ROOT / "models" / "scaler.pkl")

feature_cols = [
    "request_count","unique_urls","avg_bytes","total_bytes",
    "error_rate","status_404","status_500","post_rate",
    "url_diversity","bytes_per_req","error_to_ok_ratio",
    "max_bytes","large_req_count"
]

test_cases = {
    "Normal user (browsing)": [5, 3, 1200, 6000, 0.0, 0, 0, 0.1, 0.6, 1200, 0.0, 200, 0.0 ],
    "Scanner (high 404s)":    [500, 450, 200, 100000, 0.9, 420, 5, 0.0, 0.9, 200, 8.4, 200, 0.0],
    "DDoS (flood)":           [2000, 2, 100, 200000, 0.1, 10, 0, 0.0, 0.001, 100, 0.1, 200, 0.0],
    "Data exfil (big bytes)": [10, 8, 95000, 950000, 0.0, 0, 0, 0.8, 0.8, 95000, 0.0, 100000, 50],
    "Brute force (POST)":     [300, 1, 400, 120000, 0.95, 0, 10, 0.99, 0.003, 400, 0.0, 300, 0.0],
}

print(f"\n{'Test case':<30} {'Score':>8}  {'Result'}")
print("─" * 55)
for name, values in test_cases.items():
    X = scaler.transform(np.array(values).reshape(1, -1))
    score  = model.decision_function(X)[0]
    label  = model.predict(X)[0]
    result = "⚠ ANOMALY" if label == -1 else "✓ normal"
    print(f"{name:<30} {score:>8.4f}  {result}")
