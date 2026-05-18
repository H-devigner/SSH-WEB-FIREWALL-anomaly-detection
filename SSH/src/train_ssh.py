from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from ssh_features import FEATURES


ROOT = Path(__file__).resolve().parents[1]
FEATURES_CSV = ROOT / "data" / "processed" / "ssh_features.csv"
MODELS_DIR = ROOT / "models"


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(FEATURES_CSV)

    normal = df[df["pseudo_label"] == 0].copy()
    if len(normal) < 50:
        normal = df.nsmallest(max(50, int(len(df) * 0.25)), "burst_score").copy()

    X_full = normal[FEATURES].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_full)
    X_train, X_test = train_test_split(X_scaled, test_size=0.25, random_state=42)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.12,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    joblib.dump(model, MODELS_DIR / "ssh_isolation.pkl")
    joblib.dump(
        {
            "scaler": scaler,
            "features": FEATURES,
            "X_test_normal": X_test,
            "train_rows": len(X_train),
            "test_rows": len(X_test),
        },
        MODELS_DIR / "ssh_scaler.pkl",
    )

    print(f"Normal baseline rows: {len(normal):,}")
    print(f"Training rows: {len(X_train):,}")
    print(f"Held-out normal rows: {len(X_test):,}")
    print("Saved models/ssh_isolation.pkl and models/ssh_scaler.pkl")


if __name__ == "__main__":
    main()
