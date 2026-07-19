import argparse

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import OneHotEncoder


DEFAULT_FEATURES = ["duration", "src_bytes", "dst_bytes"]
OPTIONAL_NUMERIC_FEATURES = ["packets", "src_port", "dst_port"]
OPTIONAL_CATEGORICAL_FEATURES = ["protocol"]


def build_demo_traffic() -> pd.DataFrame:
    np.random.seed(42)

    n_normal = 500
    n_anomalies = 20

    normal_data = {
        "duration": np.random.normal(60, 10, n_normal),
        "src_bytes": np.random.normal(300, 50, n_normal),
        "dst_bytes": np.random.normal(200, 30, n_normal),
        "packets": np.random.normal(40, 8, n_normal),
        "protocol": np.random.choice(["TCP", "UDP"], n_normal, p=[0.8, 0.2]),
    }
    anomaly_data = {
        "duration": np.random.normal(200, 50, n_anomalies),
        "src_bytes": np.random.normal(2000, 500, n_anomalies),
        "dst_bytes": np.random.normal(50, 10, n_anomalies),
        "packets": np.random.normal(120, 20, n_anomalies),
        "protocol": np.random.choice(["TCP", "UDP", "ICMP"], n_anomalies),
    }

    return pd.concat([pd.DataFrame(normal_data), pd.DataFrame(anomaly_data)], ignore_index=True)


def load_traffic(input_path: str | None) -> pd.DataFrame:
    if input_path is None:
        return build_demo_traffic()

    return pd.read_csv(input_path)


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    features = df.copy()

    if {"src_bytes", "dst_bytes"}.issubset(features.columns):
        features["total_bytes"] = features["src_bytes"] + features["dst_bytes"]

    if {"src_bytes", "dst_bytes", "duration"}.issubset(features.columns):
        safe_duration = features["duration"].replace(0, np.nan)
        features["bytes_per_second"] = (features["src_bytes"] + features["dst_bytes"]) / safe_duration

    if {"src_bytes", "dst_bytes", "packets"}.issubset(features.columns):
        safe_packets = features["packets"].replace(0, np.nan)
        features["avg_packet_size"] = (features["src_bytes"] + features["dst_bytes"]) / safe_packets

    return features


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    missing = [column for column in DEFAULT_FEATURES if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    enriched = add_derived_features(df)
    numeric_columns = [
        column
        for column in DEFAULT_FEATURES + OPTIONAL_NUMERIC_FEATURES + ["total_bytes", "bytes_per_second", "avg_packet_size"]
        if column in enriched.columns
    ]

    numeric_features = enriched[numeric_columns].apply(pd.to_numeric, errors="coerce")
    numeric_features = numeric_features.replace([np.inf, -np.inf], np.nan)
    numeric_features = numeric_features.fillna(numeric_features.median(numeric_only=True))

    categorical_columns = [column for column in OPTIONAL_CATEGORICAL_FEATURES if column in enriched.columns]
    if not categorical_columns:
        return numeric_features

    encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    encoded = encoder.fit_transform(enriched[categorical_columns].fillna("unknown"))
    encoded_columns = encoder.get_feature_names_out(categorical_columns)
    categorical_features = pd.DataFrame(encoded, columns=encoded_columns, index=enriched.index)

    return pd.concat([numeric_features, categorical_features], axis=1)


def detect_anomalies(df: pd.DataFrame, contamination: float) -> pd.DataFrame:
    feature_matrix = build_feature_matrix(df)
    model = IsolationForest(contamination=contamination, random_state=42)

    result = df.copy()
    result["anomaly"] = model.fit_predict(feature_matrix)
    result["anomaly_score"] = model.decision_function(feature_matrix)

    return result.sort_values("anomaly_score")


def plot_anomalies(result: pd.DataFrame) -> None:
    fig = plt.figure(figsize=(10, 7))
    ax = fig.add_subplot(111, projection="3d")

    normal = result[result["anomaly"] == 1]
    anomalies = result[result["anomaly"] == -1]

    ax.scatter(normal["duration"], normal["src_bytes"], normal["dst_bytes"], c="green", label="normal", s=30)
    ax.scatter(anomalies["duration"], anomalies["src_bytes"], anomalies["dst_bytes"], c="red", label="anomaly", s=50, marker="x")

    ax.set_xlabel("Duration (sec)")
    ax.set_ylabel("Source bytes")
    ax.set_zlabel("Destination bytes")
    ax.set_title("Network Traffic Anomaly Detection (3D)")
    ax.legend()
    plt.tight_layout()
    plt.show()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect anomalies in network traffic CSV data.")
    parser.add_argument("--input", help="Path to a network traffic CSV file.")
    parser.add_argument("--output", default="anomalies.csv", help="Where to save detected anomalies.")
    parser.add_argument("--contamination", type=float, default=0.04, help="Expected anomaly ratio, from 0.0 to 0.5.")
    parser.add_argument("--plot", action="store_true", help="Show a 3D anomaly plot.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    df = load_traffic(args.input)
    result = detect_anomalies(df, args.contamination)
    anomalies = result[result["anomaly"] == -1]

    anomalies.to_csv(args.output, index=False)
    print(f"Rows analyzed: {len(result)}")
    print(f"Detected anomalies: {len(anomalies)}")
    print(f"Saved anomalies to: {args.output}")
    print(anomalies.head(20))

    if args.plot:
        plot_anomalies(result)


if __name__ == "__main__":
    main()
