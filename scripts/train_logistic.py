import argparse
import pandas as pd
import pickle
import json
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

def train_model(data_path: str, output_model: str):
    print(f"Loading data from {data_path}...")
    try:
        df = pd.read_csv(data_path)
    except Exception as e:
        print(f"Failed to read CSV: {e}")
        return

    if df.empty:
        print("Dataset is empty.")
        return
        
    print(f"Dataset shape: {df.shape}")
    print("Class balance:")
    print(df['label'].value_counts(normalize=True))
    
    target = 'label'
    features = [c for c in df.columns if c != target]
    
    X = df[features]
    y = df[target]
    
    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Model
    # simplistic logistic regression
    clf = LogisticRegression(class_weight='balanced', max_iter=1000)
    clf.fit(X_train, y_train)
    
    # Eval
    probs = clf.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, probs) if len(set(y_test)) > 1 else 0.0
    print(f"Test AUC: {auc:.3f}")
    
    # Save Model
    print(f"Saving model to {output_model}...")
    with open(output_model, "wb") as f:
        pickle.dump(clf, f)
        
    # Save Metadata (Features list)
    meta = {
        "features": features,
        "metrics": {"auc": auc},
        "model_type": "LogisticRegression"
    }
    with open(output_model + ".meta.json", "w") as f:
        json.dump(meta, f, indent=2)
        
    print("Done.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="training_data.csv")
    parser.add_argument("--out", default="riskbot/scoring/model_v1.pkl")
    args = parser.parse_args()
    train_model(args.data, args.out)
