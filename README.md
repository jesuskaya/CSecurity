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

Required CSV columns:

```text
duration, src_bytes, dst_bytes
```

Optional columns used when present:

```text
packets, src_port, dst_port, protocol
```

The script saves suspicious rows to `anomalies.csv` and adds `anomaly` plus `anomaly_score` columns.
