import sqlite3
import pandas as pd
import json
import pickle
import os
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from compliancebot.config import DB_PATH

MODEL_PATH = "data/model.pkl"

def load_data():
    """Load and join runs with labels."""
    conn = sqlite3.connect(DB_PATH)
    
    # Join pr_runs with pr_labels
    # We only want runs that have labels
    query = """
    SELECT 
        r.features_json,
        l.label_type
    FROM pr_runs r
    JOIN pr_labels l ON r.repo = l.repo AND r.pr_number = l.pr_number
    """
    
    df = pd.read_sql_query(query, conn)
    conn.close()
    
    return df

def preprocess(df):
    """Convert raw features into training format."""
    if df.empty:
        print("No labeled data found.")
        return None, None
    
    # 1. Expand features from JSON
    # features_json contains: diff (lines added/deleted), files (count), tests (bool), etc.
    features_list = df['features_json'].apply(json.loads).tolist()
    X = pd.json_normalize(features_list)
    
    # Select relevant columns (flattened)
    # Adjust these based on actual JSON structure. 
    # Example: diff.lines_added, diff.lines_deleted, churn.total_commits, tests.count, etc.
    # For now, we'll try to use whatever columns exist, filling NaNs
    
    # 2. Target Encoding
    # 1 = Risky (incident, rollback), 0 = Safe (safe, hotfix)
    # Note: 'hotfix' is tricky. Usually a hotfix PR itself is risky, but if we are labeling the *outcome* of a PR...
    # If the label means "This PR CAUSED an incident", then incident=1.
    # If the label means "This PR WAS a hotfix", it might be risky or safe depending on intent.
    # User spec: Target: 1 if label in ['incident', 'rollback'], 0 if ['safe', 'hotfix'].
    
    risky_labels = ['incident', 'rollback', 'bad']
    y = df['label_type'].apply(lambda x: 1 if x in risky_labels else 0)
    
    # 3. Cleanup X
    # Drop non-numeric columns if any exist after normalization (like file paths in lists)
    # We need to be careful. For V3.0 infrastructure, we'll just select numeric types.
    X = X.select_dtypes(include=['number', 'bool'])
    
    # Fill NaNs
    imputer = SimpleImputer(strategy='constant', fill_value=0)
    X_imputed = pd.DataFrame(imputer.fit_transform(X), columns=X.columns)
    
    return X_imputed, y

def train():
    print("Loading data from SQLite...")
    df = load_data()
    
    X, y = preprocess(df)
    
    if X is None or len(X) < 5:
        print("Not enough labeled data to train (need at least 5 rows).")
        return
    
    print(f"Training on {len(X)} examples...")
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Model
    # Using LogisticRegression for V3.0 as it's less prone to overfitting on small data
    model = LogisticRegression(class_weight='balanced')
    model.fit(X_train, y_train)
    
    # Evaluate
    score = model.score(X_test, y_test)
    print(f"Test Accuracy: {score:.2f}")
    
    # Save
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    train()
