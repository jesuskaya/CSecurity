# CSecurity Mini Log Analyzer

This is a small Python tool I built to speed up basic log triage. It scans log files for public IPv4 addresses, highlights suspicious IPs based on repeated hits and security-related keywords, and can optionally enrich those IPs with VirusTotal results.

## Features

- Extracts public IPv4 addresses from log files
- Flags suspicious IPs using simple keyword and frequency heuristics
- Supports local secret loading from `.env`
- Can enrich findings with VirusTotal
- Can export results to JSON for later analysis

## Setup

1. Create a virtual environment if needed.
2. Copy `.env.example` to `.env`.
3. Put your VirusTotal API key into `.env`.

Example `.env`:

```env
VT_API_KEY=your_virustotal_api_key
```

## Usage

```powershell
python .\main.py .\path\to\log.txt
python .\main.py .\path\to\log.txt --vt-check
python .\main.py .\path\to\log.txt --json-output .\report.json
```

## Notes

- `.env` is ignored by Git to avoid leaking secrets.
- `.env.example` is included as a safe template.
- This project is meant as a lightweight log triage helper, not a full SIEM replacement.
