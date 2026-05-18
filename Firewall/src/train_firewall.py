from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parents[1]
MODELS_DIR = ROOT / "models"


def main() -> None:
    pipeline = joblib.load(MODELS_DIR / "firewall_scaler.pkl")
    scaler = pipeline["scaler"]
    x_train_full = pipeline["X_train_full"]
    features = pipeline["features"]

    x_train, x_test = train_test_split(x_train_full, test_size=0.2, random_state=42)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.35,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(x_train)

    joblib.dump(model, MODELS_DIR / "firewall_isolation.pkl")
    joblib.dump(
        {
            "scaler": scaler,
            "features": features,
            "X_test_normal": x_test,
            "train_rows": len(x_train),
            "test_rows": len(x_test),
        },
        MODELS_DIR / "firewall_scaler_test.pkl",
    )

    print(f"Training rows: {len(x_train):,}")
    print(f"Held-out normal rows: {len(x_test):,}")
    print("Saved models/firewall_isolation.pkl and models/firewall_scaler_test.pkl")


if __name__ == "__main__":
    main()
