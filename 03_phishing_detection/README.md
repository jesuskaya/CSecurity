# Phishing Detection Automation

Automation project for identifying suspicious URLs, domains, and email indicators.

## Goal

Build a tool that can analyze phishing indicators and flag risky items for review.

## Planned Inputs

```text
url, domain, sender_email, subject, body_preview
```

## Planned Checks

- suspicious URL length
- IP address used instead of a domain
- unusual top-level domain
- excessive subdomains
- suspicious keywords
- domain age or reputation enrichment
- mismatch between sender and link domain

## Planned Output

```text
indicator, risk_score, reasons
```

## Structure

- `data/` - local samples and test CSV files
- `src/` - phishing detection source code
- `requirements.txt` - Python dependencies
