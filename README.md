# CyberSecurity Automatization

Repository for small cybersecurity automation practice projects.

## Projects

- `01_mini_log_analyzer/` - Mini Log Analyzer for basic log triage and optional VirusTotal enrichment.
- `02_anomaly_detection/` - Network traffic anomaly detection with Python, Pandas, and Scikit-learn.

## Network Traffic Anomaly Detection

Run the demo dataset:

```powershell
.\.venv\Scripts\python.exe 02_anomaly_detection/anomaly_det.py --output anomalies.csv
```

Run detection on a real CSV export:

```powershell
.\.venv\Scripts\python.exe 02_anomaly_detection/anomaly_det.py --input traffic.csv --output anomalies.csv
```

Run detection on CIC-IDS2017 DDoS traffic:

```powershell
.\.venv\Scripts\python.exe 02_anomaly_detection/anomaly_det.py --input "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv" --output anomalies.csv
```

Required CSV columns:

```text
Flow Duration, Total Length of Fwd Packets, Total Length of Bwd Packets
```

Optional columns used when present:

```text
Destination Port, Protocol, Total Fwd Packets, Total Backward Packets, Flow Bytes/s, Flow Packets/s, Average Packet Size, Label
```

The script saves suspicious rows to `anomalies.csv`, keeps `Label` when present, and adds `anomaly` plus `anomaly_score` columns.
