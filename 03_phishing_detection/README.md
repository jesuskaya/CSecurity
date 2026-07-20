# Phishing Detection Automation

Automation project for identifying suspicious URLs, domains, and email indicators.

## Goal

Train a text classifier that detects phishing email content and prints model quality plus a sample phishing probability.

## Usage

From the repository root:

```powershell
python 03_phishing_detection/antiphishing.py
```

## Input

```text
phishing_emails_dataset.csv
```

Required columns:

```text
text, label
```

## Output

```text
classification report
top phishing words
top legitimate words
sample phishing probability
```

## Structure

- `data/` - local samples and test CSV files
- `src/` - phishing detection source code
- `requirements.txt` - Python dependencies
