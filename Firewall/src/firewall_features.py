from pathlib import Path

import pandas as pd


FEATURES = [
    "Source Port",
    "Destination Port",
    "Bytes",
    "Packets",
    "Elapsed Time (sec)",
    "Bytes_per_Packet",
    "Packet_Rate",
    "Byte_Rate",
    "Port_Diversity_Ratio",
]


def load_firewall_data(path: Path) -> pd.DataFrame:
    return pd.read_csv(path)


def add_firewall_features(df: pd.DataFrame) -> pd.DataFrame:
    featured = df.copy()
    featured["Bytes_per_Packet"] = featured["Bytes"] / (featured["Packets"] + 1)
    featured["Packet_Rate"] = featured["Packets"] / (featured["Elapsed Time (sec)"] + 0.001)
    featured["Byte_Rate"] = featured["Bytes"] / (featured["Elapsed Time (sec)"] + 0.001)
    featured["Port_Diversity_Ratio"] = featured["Destination Port"] / (featured["Source Port"] + 1)
    return featured
