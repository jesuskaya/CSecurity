# Phishing Detection Automation

Train and run a phishing email detector for SOC triage.

## Dataset

The training CSV must contain:

```text
text, label
```

`label` values:

```text
0 = legitimate
1 = phishing
```

## Train

```powershell
python 03_phishing_detection/antiphishing.py train
```

This saves:

```text
03_phishing_detection/model/phishing_model.pkl
03_phishing_detection/model/tfidf_vectorizer.pkl
```

## Predict One Email

```powershell
python 03_phishing_detection/antiphishing.py predict --text "Your mailbox is full. Verify your account now."
```

Or from a text file:

```powershell
python 03_phishing_detection/antiphishing.py predict --file suspicious_email.txt
```

Included sample:

```powershell
python 03_phishing_detection/antiphishing.py predict --file 03_phishing_detection/data/suspicious_email.txt
```

## Batch Scan

Input CSV must contain a `text` column.

```powershell
python 03_phishing_detection/antiphishing.py batch --input emails.csv --output phishing_results.csv
```

Included sample:

```powershell
python 03_phishing_detection/antiphishing.py batch --input 03_phishing_detection/data/sample_emails.csv --output phishing_results.csv
```

## Output

The detector returns:

```text
phishing_probability
prediction
risk_level
top_suspicious_terms
```

## Notes

This is a triage tool, not a final verdict. High scores should be reviewed with email headers, sender reputation, URLs, attachments, and user context.
