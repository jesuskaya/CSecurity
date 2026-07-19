# Network Traffic Anomaly Detection

Detect suspicious network traffic rows with `IsolationForest`.

## Usage

Run with demo data:

```powershell
..\.venv\Scripts\python.exe anomaly_det.py --output anomalies.csv
```

Run with a CIC-IDS2017 CSV export:

```powershell
..\.venv\Scripts\python.exe anomaly_det.py --input "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" --output cic_anomalies.csv
```

Run the included small CIC-like sample:

```powershell
..\.venv\Scripts\python.exe anomaly_det.py --input data\cic_ids_sample.csv --output cic_anomalies.csv --contamination 0.2
```

From the repository root:

```powershell
.\.venv\Scripts\python.exe 02_anomaly_detection/anomaly_det.py --input traffic.csv --output anomalies.csv
```

## CSV Format

Required columns:

```text
Flow Duration, Total Length of Fwd Packets, Total Length of Bwd Packets
```

Optional columns:

```text
Destination Port, Protocol, Total Fwd Packets, Total Backward Packets, Flow Bytes/s, Flow Packets/s, Average Packet Size
```

The `Label` column is not used for training, but it is kept in output and used for evaluation when present.

The script prints:

```text
Label distribution among anomalies
Total attacks
Attacks detected as anomalies
BENIGN false positives
Attack recall
```

## Output

The output CSV contains only detected suspicious rows and adds:

```text
anomaly, anomaly_score
```

Lower `anomaly_score` values are more suspicious.

## Notes

This script detects unusual traffic, not confirmed malicious activity. Use the output as a triage list for analyst review.
