from pathlib import Path

import joblib
from sklearn.preprocessing import StandardScaler

from firewall_features import FEATURES, add_firewall_features, load_firewall_data


ROOT = Path(__file__).resolve().parents[1]
DATA_CSV = ROOT / "data" / "raw" / "firewall.csv"
MODELS_DIR = ROOT / "models"


def main() -> None:
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = add_firewall_features(load_firewall_data(DATA_CSV))
    normal = df[df["Action"] == "allow"][FEATURES].dropna()

    scaler = StandardScaler()
    x_train_full = scaler.fit_transform(normal)

    joblib.dump(
        {
            "scaler": scaler,
            "features": FEATURES,
            "X_train_full": x_train_full,
            "normal_rows": len(normal),
        },
        MODELS_DIR / "firewall_scaler.pkl",
    )

    print(f"Normal baseline rows: {len(normal):,}")
    print("Saved models/firewall_scaler.pkl")


if __name__ == "__main__":
    main()
