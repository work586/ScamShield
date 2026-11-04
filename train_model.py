# train_model.py
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle
import os

print("🧠 Starting Machine Learning Training...")

# 1. Load the dataset from the data folder
csv_path = os.path.join('data', 'spam.csv')

# The UCI dataset uses 'latin-1' encoding and has weird column names
df = pd.read_csv(csv_path, encoding='latin-1')
df = df[['v1', 'v2']]        # Keep only label and text columns
df.columns = ['label', 'text'] # Rename them

# Convert 'ham' to 0 and 'spam' to 1
df['label'] = df['label'].map({'ham': 0, 'spam': 1})

print(f"Loaded {len(df)} messages for training...")

# 2. Convert text into numbers (TF-IDF Vectorization)
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X = vectorizer.fit_transform(df['text'])
y = df['label']

# 3. Train the AI Model (Naive Bayes)
model = MultinomialNB()
model.fit(X, y)

# 4. Save the trained model and vectorizer to files
with open('model.pkl', 'wb') as f:
    pickle.dump(model, f)
    
with open('vectorizer.pkl', 'wb') as f:
    pickle.dump(vectorizer, f)

print("✅ Training Complete! model.pkl and vectorizer.pkl saved.")