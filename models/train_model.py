"""
Isolation Forest Model Training Script

Generates synthetic training data from the log generator and trains an
Isolation Forest model for anomaly detection. The trained model is
serialized to disk for use by the streaming processor.
"""

import os
import sys
import json
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import joblib

from config.settings import (
    MODEL_PATH, MODEL_CONTAMINATION, MODEL_N_ESTIMATORS,
    MODEL_TRAINING_SAMPLES, FEATURE_COLUMNS,
)
from agents.log_generator import SecurityLogGenerator
from processing.log_parser import LogParser


def generate_training_data(n_samples: int) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic training data using the log generator.

    Args:
        n_samples: Number of log samples to generate.

    Returns:
        Tuple of (feature_matrix, labels) where labels are 1=normal, -1=anomaly.
    """
    print(f"[Training] Generating {n_samples} synthetic log samples...")
    generator = SecurityLogGenerator("training-agent")

    features_list = []
    labels = []

    for i in range(n_samples):
        log = generator.generate_log()
        features = LogParser.extract_features(log)
        features_list.append(features)
        labels.append(-1 if log.get("is_anomaly", False) else 1)

        if (i + 1) % 2000 == 0:
            print(f"  Generated {i + 1}/{n_samples} samples...")

    X = np.array(features_list)
    y = np.array(labels)

    n_normal = np.sum(y == 1)
    n_anomaly = np.sum(y == -1)
    print(f"[Training] Dataset: {n_normal} normal, {n_anomaly} anomalous "
          f"({n_anomaly / n_samples * 100:.1f}% anomaly rate)")

    return X, y


def train_model(X: np.ndarray, y: np.ndarray) -> IsolationForest:
    """
    Train an Isolation Forest model.

    Args:
        X: Feature matrix.
        y: True labels (used for evaluation only, not training).

    Returns:
        Trained IsolationForest model.
    """
    print(f"\n[Training] Training Isolation Forest...")
    print(f"  Estimators:    {MODEL_N_ESTIMATORS}")
    print(f"  Contamination: {MODEL_CONTAMINATION}")
    print(f"  Features:      {len(FEATURE_COLUMNS)}")

    model = IsolationForest(
        n_estimators=MODEL_N_ESTIMATORS,
        contamination=MODEL_CONTAMINATION,
        max_samples="auto",
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
        verbose=0,
    )

    model.fit(X)
    print("[Training] Model trained successfully.")

    return model


def evaluate_model(model: IsolationForest, X: np.ndarray, y_true: np.ndarray):
    """Evaluate the trained model against ground truth labels."""
    print("\n[Evaluation] Running predictions on training data...")

    y_pred = model.predict(X)
    scores = model.decision_function(X)

    print("\n  Classification Report:")
    target_names = ["Anomaly (-1)", "Normal (1)"]
    report = classification_report(y_true, y_pred, target_names=target_names)
    print(report)

    cm = confusion_matrix(y_true, y_pred)
    print(f"  Confusion Matrix:")
    print(f"                Pred Anomaly  Pred Normal")
    print(f"  True Anomaly  {cm[0][0]:>12}  {cm[0][1]:>11}")
    print(f"  True Normal   {cm[1][0]:>12}  {cm[1][1]:>11}")

    print(f"\n  Score Statistics:")
    print(f"    Mean score (normal):  {scores[y_true == 1].mean():.4f}")
    print(f"    Mean score (anomaly): {scores[y_true == -1].mean():.4f}")
    print(f"    Threshold:            {model.offset_:.4f}")


def save_model(model: IsolationForest, path: str):
    """Save the trained model to disk."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    file_size = os.path.getsize(path) / 1024
    print(f"\n[Training] Model saved to {path} ({file_size:.1f} KB)")


def main():
    """Main training pipeline."""
    print("\n" + "=" * 60)
    print("  Isolation Forest Model Training")
    print("=" * 60)

    # Generate training data
    X, y = generate_training_data(MODEL_TRAINING_SAMPLES)

    # Train the model
    model = train_model(X, y)

    # Evaluate
    evaluate_model(model, X, y)

    # Save
    save_model(model, MODEL_PATH)

    print("\n" + "=" * 60)
    print("  Training Complete!")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
