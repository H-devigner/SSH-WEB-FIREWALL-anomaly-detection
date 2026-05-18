from pathlib import Path
import tarfile

from ssh_features import build_feature_table, parse_ssh_logs


ROOT = Path(__file__).resolve().parents[1]
RAW_ROOT = ROOT / "data" / "raw" / "dataset1"
ARCHIVE = ROOT / "data" / "raw" / "dataset1_log_files.tgz"
PROCESSED_DIR = ROOT / "data" / "processed"


def ensure_raw_dataset() -> None:
    if RAW_ROOT.exists():
        return
    if not ARCHIVE.exists():
        raise FileNotFoundError(
            f"Missing {ARCHIVE}. Download dataset1_log_files.tgz before preprocessing."
        )
    destination = (ROOT / "data" / "raw").resolve()
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if destination != target and destination not in target.parents:
                raise RuntimeError(f"Unsafe archive path: {member.name}")
        archive.extractall(destination)


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    ensure_raw_dataset()
    events = parse_ssh_logs(RAW_ROOT)
    features = build_feature_table(events)

    events.head(5000).to_csv(PROCESSED_DIR / "ssh_events_sample.csv", index=False)
    features.to_csv(PROCESSED_DIR / "ssh_features.csv", index=False)

    print(f"Parsed SSH events: {len(events):,}")
    print(f"Feature windows: {len(features):,}")
    print("Pseudo-label distribution:")
    print(features["pseudo_label"].value_counts().rename({0: "normal", 1: "anomaly"}).to_string())
    print("Saved data/processed/ssh_events_sample.csv and data/processed/ssh_features.csv")


if __name__ == "__main__":
    main()
