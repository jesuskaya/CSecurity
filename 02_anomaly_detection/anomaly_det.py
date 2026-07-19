import argparse

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


DEFAULT_FEATURES = ["Flow Duration", "Total Length of Fwd Packets", "Total Length of Bwd Packets"]
OPTIONAL_NUMERIC_FEATURES = [
    "Destination Port",
    "Protocol",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size",
]


def build_demo_traffic() -> pd.DataFrame:
    np.random.seed(42)

    n_normal = 500
    n_anomalies = 20

    normal_data = {
        "Destination Port": np.random.choice([53, 80, 443, 8080], n_normal),
        "Protocol": np.random.choice([6, 17], n_normal, p=[0.8, 0.2]),
        "Flow Duration": np.random.normal(60_000, 10_000, n_normal),
        "Total Fwd Packets": np.random.normal(20, 5, n_normal),
        "Total Backward Packets": np.random.normal(18, 5, n_normal),
        "Total Length of Fwd Packets": np.random.normal(300, 50, n_normal),
        "Total Length of Bwd Packets": np.random.normal(200, 30, n_normal),
        "Flow Bytes/s": np.random.normal(8, 2, n_normal),
        "Flow Packets/s": np.random.normal(0.6, 0.2, n_normal),
        "Average Packet Size": np.random.normal(14, 3, n_normal),
        "Label": "BENIGN",
    }
    anomaly_data = {
        "Destination Port": np.random.choice([4444, 6667, 3389], n_anomalies),
        "Protocol": np.random.choice([6, 17], n_anomalies),
        "Flow Duration": np.random.normal(8_000_000, 1_000_000, n_anomalies),
        "Total Fwd Packets": np.random.normal(80, 15, n_anomalies),
        "Total Backward Packets": np.random.normal(3, 1, n_anomalies),
        "Total Length of Fwd Packets": np.random.normal(800_000, 100_000, n_anomalies),
        "Total Length of Bwd Packets": np.random.normal(100, 20, n_anomalies),
        "Flow Bytes/s": np.random.normal(1200, 200, n_anomalies),
        "Flow Packets/s": np.random.normal(10, 2, n_anomalies),
        "Average Packet Size": np.random.normal(9500, 1000, n_anomalies),
        "Label": "DDoS",
    }

    return pd.concat([pd.DataFrame(normal_data), pd.DataFrame(anomaly_data)], ignore_index=True)


def load_traffic(input_path: str | None) -> pd.DataFrame:
    if input_path is None:
        return build_demo_traffic()

    df = pd.read_csv(input_path)
    df.columns = df.columns.str.strip()
    return df


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    missing = [column for column in DEFAULT_FEATURES if column not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")

    numeric_columns = [column for column in DEFAULT_FEATURES + OPTIONAL_NUMERIC_FEATURES if column in df.columns]
    numeric_features = df[numeric_columns].apply(pd.to_numeric, errors="coerce")
    numeric_features = numeric_features.replace([np.inf, -np.inf], np.nan)
    numeric_features = numeric_features.fillna(numeric_features.median(numeric_only=True))
    return numeric_features.fillna(0)


def detect_anomalies(df: pd.DataFrame, contamination: float) -> pd.DataFrame:
    if contamination <= 0 or contamination > 0.5:
        raise ValueError("contamination must be greater than 0 and less than or equal to 0.5")

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

    ax.scatter(
        normal["Flow Duration"],
        normal["Total Length of Fwd Packets"],
        normal["Total Length of Bwd Packets"],
        c="green",
        label="normal",
        s=30,
    )
    ax.scatter(
        anomalies["Flow Duration"],
        anomalies["Total Length of Fwd Packets"],
        anomalies["Total Length of Bwd Packets"],
        c="red",
        label="anomaly",
        s=50,
        marker="x",
    )

    ax.set_xlabel("Flow Duration")
    ax.set_ylabel("Total Length of Fwd Packets")
    ax.set_zlabel("Total Length of Bwd Packets")
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

    if "Label" in result.columns:
        print("Anomaly labels:")
        print(anomalies["Label"].value_counts())

        attacks = result["Label"] != "BENIGN"
        detected = result["anomaly"] == -1
        total_attacks = int(attacks.sum())
        detected_attacks = int((attacks & detected).sum())
        false_positive_benign = int(((result["Label"] == "BENIGN") & detected).sum())
        recall = detected_attacks / total_attacks if total_attacks else 0

        print(f"Total attacks: {total_attacks}")
        print(f"Attacks detected as anomalies: {detected_attacks}")
        print(f"BENIGN flows incorrectly marked as anomalies: {false_positive_benign}")
        print(f"Attack recall: {recall:.4f}")

    if args.plot:
        plot_anomalies(result)


if __name__ == "__main__":
    main()
