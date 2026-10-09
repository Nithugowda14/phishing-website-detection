"""
Prediction Module for Phishing Website Detection System.
Loads the trained ML model, runs feature extraction on incoming URLs,
and performs inference with probability and confidence metrics.
"""

import os
from typing import Dict, Any, Optional
import joblib
import pandas as pd

try:
    from src.feature_extraction import (
        MODEL_FEATURE_NAMES,
        extract_features,
        get_display_features,
        normalize_url
    )
except ImportError:
    from feature_extraction import (
        MODEL_FEATURE_NAMES,
        extract_features,
        get_display_features,
        normalize_url
    )

# Global model cache to avoid repeated disk I/O on every prediction request
_MODEL_CACHE = None


def load_model(model_path: Optional[str] = None):
    """
    Load trained model from joblib file with caching.
    """
    global _MODEL_CACHE
    if _MODEL_CACHE is not None and model_path is None:
        return _MODEL_CACHE

    if model_path is None:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        model_path = os.path.join(base_dir, "model", "phishing_model.pkl")

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Trained model not found at '{model_path}'. "
            "Please run 'python src/train_model.py' to train and generate the model first."
        )

    loaded = joblib.load(model_path)
    
    # Handle either raw estimator or dictionary artifact
    if isinstance(loaded, dict) and "model" in loaded:
        _MODEL_CACHE = loaded["model"]
    else:
        _MODEL_CACHE = loaded

    return _MODEL_CACHE


def predict_url(raw_url: str, model_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Analyze a given URL string and return classification prediction and feature breakdown.
    
    Args:
        raw_url: Website URL to inspect.
        model_path: Optional path to custom model artifact.
        
    Returns:
        dict: Detailed prediction results, confidence score, and feature attributes.
    """
    if not raw_url or not raw_url.strip():
        raise ValueError("URL cannot be empty.")

    cleaned_url = raw_url.strip()
    norm_url = normalize_url(cleaned_url)

    # 1. Extract feature dictionary
    feat_dict = extract_features(norm_url)

    # 2. Format features as single-row DataFrame matching training feature columns
    feat_df = pd.DataFrame([feat_dict])[MODEL_FEATURE_NAMES]

    # 3. Load model and predict
    model = load_model(model_path)
    prediction = int(model.predict(feat_df)[0])
    probabilities = model.predict_proba(feat_df)[0]

    prob_legit = float(probabilities[0])
    prob_phish = float(probabilities[1])

    # Confidence score is the probability of the predicted class
    confidence = prob_phish if prediction == 1 else prob_legit

    # Friendly human-readable label
    label = "Phishing" if prediction == 1 else "Legitimate"

    # Display-ready feature list for UI
    display_features = get_display_features(norm_url)

    return {
        "url": cleaned_url,
        "normalized_url": norm_url,
        "prediction": prediction,
        "label": label,
        "confidence": round(confidence, 4),
        "probability_legitimate": round(prob_legit, 4),
        "probability_phishing": round(prob_phish, 4),
        "features": feat_dict,
        "display_features": display_features
    }
