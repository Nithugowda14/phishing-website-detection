"""
Model Training and Evaluation Module for Phishing Website Detection System.
Trains a Scikit-Learn Random Forest Classifier, evaluates performance metrics,
generates a Confusion Matrix plot, and saves the trained model with Joblib.
"""

import os
import sys
from datetime import datetime
import joblib
import numpy as np
import pandas as pd

# Set matplotlib headless backend before importing pyplot
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    ConfusionMatrixDisplay
)

# Handle relative or absolute module imports
try:
    from src.data_preprocessing import (
        load_dataset,
        clean_and_prepare_data,
        get_feature_target_split,
        split_data,
        get_dataset_summary
    )
    from src.feature_extraction import MODEL_FEATURE_NAMES
except ImportError:
    from data_preprocessing import (
        load_dataset,
        clean_and_prepare_data,
        get_feature_target_split,
        split_data,
        get_dataset_summary
    )
    from feature_extraction import MODEL_FEATURE_NAMES


def train_and_evaluate(
    dataset_path: str = "dataset/phishing_dataset.csv",
    model_save_path: str = "model/phishing_model.pkl",
    results_dir: str = "results"
) -> dict:
    """
    Execute full machine learning training, evaluation, and artifact generation pipeline.
    """
    print("=" * 60)
    print("  PHISHING WEBSITE DETECTION SYSTEM - ML TRAINING PIPELINE")
    print("=" * 60)

    # 1. Resolve file paths relative to project root
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    full_dataset_path = os.path.join(base_dir, dataset_path)
    full_model_path = os.path.join(base_dir, model_save_path)
    full_results_dir = os.path.join(base_dir, results_dir)

    os.makedirs(os.path.dirname(full_model_path), exist_ok=True)
    os.makedirs(full_results_dir, exist_ok=True)

    # 2. Load and inspect dataset
    print(f"\n[1/6] Loading dataset from: {full_dataset_path}")
    raw_df = load_dataset(full_dataset_path)
    summary = get_dataset_summary(raw_df)
    print(f"      Total records: {summary['total_samples']}")
    print(f"      Legitimate (0): {summary['legitimate_samples']} ({summary['legitimate_percentage']}%)")
    print(f"      Phishing (1):   {summary['phishing_samples']} ({summary['phishing_percentage']}%)")

    # 3. Clean and prepare data
    print("\n[2/6] Cleaning dataset and extracting feature matrix...")
    X, y = get_feature_target_split(raw_df)
    print(f"      Model features count: {len(MODEL_FEATURE_NAMES)}")

    # 4. Train-Test Split (80% train, 20% test stratified)
    print("\n[3/6] Performing 80/20 stratified train-test split...")
    X_train, X_test, y_train, y_test = split_data(X, y, test_size=0.2, random_state=42)
    print(f"      Training samples: {len(X_train)}")
    print(f"      Testing samples:  {len(X_test)}")

    # 5. Train Random Forest Classifier
    print("\n[4/6] Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # Optional: Baseline comparison with Logistic Regression
    lr_model = LogisticRegression(max_iter=1000, random_state=42)
    lr_model.fit(X_train, y_train)
    lr_acc = accuracy_score(y_test, lr_model.predict(X_test))

    # 6. Evaluation metrics on test partition
    print("\n[5/6] Evaluating model on unseen test set...")
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"])

    print(f"      Accuracy:  {acc * 100:.2f}%")
    print(f"      Precision: {prec * 100:.2f}%")
    print(f"      Recall:    {rec * 100:.2f}%")
    print(f"      F1-Score:  {f1 * 100:.2f}%")
    print(f"      (Baseline Logistic Regression Accuracy: {lr_acc * 100:.2f}%)")

    # 7. Generate and save Confusion Matrix plot
    cm_plot_path = os.path.join(full_results_dir, "confusion_matrix.png")
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Legitimate", "Phishing"])
    disp.plot(cmap="Blues", values_format="d", ax=ax)
    ax.set_title("Phishing Detection - Confusion Matrix", fontsize=12, fontweight="bold", pad=12)
    plt.tight_layout()
    plt.savefig(cm_plot_path, dpi=200)
    plt.close()
    print(f"\n[6/6] Saved confusion matrix plot to: {cm_plot_path}")

    # 8. Feature Importances
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    feature_ranking_text = "\nFeature Importance Ranking:\n" + "-" * 40 + "\n"
    for i in range(len(MODEL_FEATURE_NAMES)):
        feature_ranking_text += f"{i+1:2d}. {MODEL_FEATURE_NAMES[indices[i]]:<28} : {importances[indices[i]]:.4f}\n"

    # 9. Save detailed model results text report
    results_txt_path = os.path.join(full_results_dir, "model_results.txt")
    report_content = f"""============================================================
PHISHING WEBSITE DETECTION SYSTEM - EVALUATION REPORT
BCA Cybersecurity Mini Project
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
============================================================

1. DATASET OVERVIEW
------------------------------------------------------------
Total Samples         : {summary['total_samples']}
Legitimate URLs (0)   : {summary['legitimate_samples']} ({summary['legitimate_percentage']}%)
Phishing URLs (1)     : {summary['phishing_samples']} ({summary['phishing_percentage']}%)
Model Features: {len(MODEL_FEATURE_NAMES)} (HTTPS is displayed but excluded from the verdict)

2. MODEL TRAINING CONFIGURATION
------------------------------------------------------------
Classifier Algorithm  : Random Forest Classifier (Scikit-Learn)
Estimators (Trees)    : 100
Maximum Tree Depth    : 10
Random State Seed     : 42
Train / Test Partition: 80% Train ({len(X_train)} samples) / 20% Test ({len(X_test)} samples)
Cross-Check Baseline  : Logistic Regression (Accuracy: {lr_acc * 100:.2f}%)

3. PERFORMANCE METRICS (ON UNSEEN TEST SET)
------------------------------------------------------------
Accuracy              : {acc * 100:.2f}%
Precision             : {prec * 100:.2f}%
Recall                : {rec * 100:.2f}%
F1-Score              : {f1 * 100:.2f}%

4. CONFUSION MATRIX
------------------------------------------------------------
                    Predicted Legit (0)    Predicted Phishing (1)
Actual Legit (0)            {cm[0][0]:<12}           {cm[0][1]:<12}
Actual Phishing (1)         {cm[1][0]:<12}           {cm[1][1]:<12}

True Negatives  (TN)  : {cm[0][0]} (Legitimate correctly identified)
False Positives (FP)  : {cm[0][1]} (Legitimate misclassified as Phishing)
False Negatives (FN)  : {cm[1][0]} (Phishing misclassified as Legitimate)
True Positives  (TP)  : {cm[1][1]} (Phishing correctly identified)

5. DETAILED CLASSIFICATION REPORT
------------------------------------------------------------
{report}

6. FEATURE IMPORTANCE RANKING
------------------------------------------------------------
{feature_ranking_text}

============================================================
CONCLUSION
The Random Forest model classifies this curated demonstration dataset
using structural anomalies, suspicious keywords, and domain patterns.
These metrics should not be treated as real-world phishing-detection performance.
============================================================
"""

    with open(results_txt_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"      Saved model results summary to: {results_txt_path}")

    # 10. Save trained model object with Joblib
    model_artifact = {
        "model": model,
        "feature_names": MODEL_FEATURE_NAMES,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1
        },
        "trained_at": datetime.now().isoformat()
    }
    joblib.dump(model_artifact, full_model_path)
    print(f"      Saved trained model artifact to: {full_model_path}")
    print("\n[SUCCESS] Model training and evaluation successfully completed!\n")

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "model_path": full_model_path
    }


if __name__ == "__main__":
    train_and_evaluate()
