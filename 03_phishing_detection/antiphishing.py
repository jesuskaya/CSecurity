import pandas as pd
import re
import nltk
from pathlib import Path

nltk.download('stopwords', quiet=True)
from nltk.corpus import stopwords
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import numpy as np

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "phishing_emails_dataset.csv"

data = pd.read_csv(DATASET_PATH)

stop_words = set(stopwords.words('english'))

def clean_text(text):
    text = re.sub(r'<.*?>', '', str(text))    # Remove HTML
    text = re.sub(r'http\S+', '', text)       # Remove links
    text = re.sub(r'[^a-zA-Z]', ' ', text)    # Keep only letters
    text = text.lower()
    text = ' '.join([word for word in text.split() if word not in stop_words])
    return text

data['clean_text'] = data['text'].apply(clean_text)

tfidf = TfidfVectorizer(max_features=5000)
X = tfidf.fit_transform(data['clean_text']).toarray()
y = data['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = LogisticRegression()
model.fit(X_train, y_train)
y_pred = model.predict(X_test)

print(classification_report(y_test, y_pred))

feature_names = tfidf.get_feature_names_out()
coefs = model.coef_[0]
top_positive = np.argsort(coefs)[-10:]
top_negative = np.argsort(coefs)[:10]

print("Top phishing words:", [feature_names[i] for i in top_positive])
print("Top legitimate words:", [feature_names[i] for i in top_negative])

sample = "We detected unusual activity on your account. Please login here to verify."
sample_clean = clean_text(sample)
sample_vector = tfidf.transform([sample_clean]).toarray()
print("Phishing probability:", model.predict_proba(sample_vector)[0][1])
