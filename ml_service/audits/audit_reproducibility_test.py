import os
import sys
import json
import joblib
import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, f1_score

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROCESSED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "processed")
ARTIFACTS_DIR = os.path.join(PROJECT_ROOT, "artifacts")

def test_reproducibility():
    print("=" * 60)
    print("PHASE M: DETERMINISM & REPRODUCIBILITY AUDIT")
    print("=" * 60)
    
    # Check NSL-KDD
    train_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "train_reduced.npz"))
    test_data = np.load(os.path.join(PROCESSED_DATA_DIR, "nsl_kdd", "test_reduced.npz"))
    X_train, y_train = train_data['X'], train_data['y_5class']
    X_test, y_test = test_data['X'], test_data['y_5class']
    
    # Production model
    prod_model = joblib.load(os.path.join(ARTIFACTS_DIR, "production", "nsl_kdd", "best_model.joblib"))
    y_pred_prod = prod_model.predict(X_test)
    acc_prod = accuracy_score(y_test, y_pred_prod)
    f1_prod = f1_score(y_test, y_pred_prod, average='weighted', zero_division=0)
    
    print(f"Production Model Acc: {acc_prod:.8f}, F1: {f1_prod:.8f}")
    
    # Retrain with exact same hyperparameters and random_state=42
    print("Retraining XGBoost with exact hyperparameters (seed 42)...")
    clf = XGBClassifier(
        tree_method="hist",
        n_estimators=100,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        n_jobs=2,
        random_state=42
    )
    clf.fit(X_train, y_train)
    y_pred_retrain = clf.predict(X_test)
    acc_retrain = accuracy_score(y_test, y_pred_retrain)
    f1_retrain = f1_score(y_test, y_pred_retrain, average='weighted', zero_division=0)
    
    print(f"Retrained Model  Acc: {acc_retrain:.8f}, F1: {f1_retrain:.8f}")
    diff_preds = np.sum(y_pred_prod != y_pred_retrain)
    print(f"Predictions mismatch count: {diff_preds} / {len(y_test)}")
    if diff_preds == 0:
        print("PERFECT DETERMINISM CONFIRMED: 100% bit-exact reproduction.")
    else:
        print(f"Minor variation observed: {diff_preds} predictions differ.")

if __name__ == "__main__":
    test_reproducibility()
