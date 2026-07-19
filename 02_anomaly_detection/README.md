# Network Traffic Anomaly Detection

Detect suspicious network traffic rows with `IsolationForest`.

## Usage

Run with demo data:

```powershell
..\.venv\Scripts\python.exe anomaly_det.py --output anomalies.csv
```

Run with a real CSV export:

```powershell
..\.venv\Scripts\python.exe anomaly_det.py --input traffic.csv --output anomalies.csv
```

Run with a CIC-IDS2017 CSV export:

```powershell
..\.venv\Scripts\python.exe anomaly_det.py --input "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" --output cic_anomalies.csv
```

From the repository root:

```powershell
.\.venv\Scripts\python.exe 02_anomaly_detection/anomaly_det.py --input traffic.csv --output anomalies.csv
```

## CSV Format

Required columns:

```text
duration, src_bytes, dst_bytes
```

Optional columns:

```text
packets, src_port, dst_port, protocol
```

CIC-IDS2017 columns are mapped automatically:

```text
Flow Duration -> duration
Total Length of Fwd Packets -> src_bytes
Total Length of Bwd Packets -> dst_bytes
Total Fwd Packets + Total Backward Packets -> packets
Destination Port -> dst_port
Protocol -> protocol
```

The script also creates derived features internally:

```text
total_bytes, bytes_per_second, avg_packet_size
```

## Output

The output CSV contains only detected suspicious rows and adds:

```text
anomaly, anomaly_score
```

Lower `anomaly_score` values are more suspicious.

## Notes

This script detects unusual traffic, not confirmed malicious activity. Use the output as a triage list for analyst review.
