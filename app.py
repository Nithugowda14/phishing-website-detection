"""
Flask Web Application for Phishing Website Detection System.
Serves frontend dashboard and processes prediction API requests.
"""

import os
import sys
from flask import Flask, render_template, request, jsonify

# Add project root to sys.path for robust module imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from src.predict import predict_url, load_model
except ImportError:
    from predict import predict_url, load_model

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or os.urandom(32)
load_model()


@app.route("/", methods=["GET"])
def home():
    """
    Renders the cybersecurity scanner homepage.
    """
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    """
    API endpoint to evaluate an input URL.
    Accepts JSON payload: { "url": "https://..." }
    or Form-encoded payload.
    """
    try:
        # 1. Parse incoming request data
        if request.is_json:
            data = request.get_json() or {}
            raw_url = data.get("url", "")
        else:
            raw_url = request.form.get("url", "")

        # 2. Validation & Sanitization
        if not raw_url or not str(raw_url).strip():
            return jsonify({
                "success": False,
                "error": "URL cannot be empty. Please enter a website address."
            }), 400

        raw_url = str(raw_url).strip()

        # Check maximum URL length to prevent buffer/DDoS abuse
        if len(raw_url) > 2048:
            return jsonify({
                "success": False,
                "error": "URL exceeds standard length limit (2048 characters)."
            }), 400

        # 3. Model Inference via predict module
        result = predict_url(raw_url)

        return jsonify({
            "success": True,
            "url": result["url"],
            "prediction": result["prediction"],
            "label": result["label"],
            "confidence": result["confidence"],
            "probability_legitimate": result["probability_legitimate"],
            "probability_phishing": result["probability_phishing"],
            "display_features": result["display_features"]
        }), 200

    except FileNotFoundError as fnf_err:
        return jsonify({
            "success": False,
            "error": "Trained machine learning model file is missing. Please run 'python src/train_model.py' to generate the model."
        }), 500

    except ValueError as val_err:
        return jsonify({
            "success": False,
            "error": str(val_err)
        }), 400

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": f"An unexpected server error occurred: {str(exc)}"
        }), 500


@app.route("/health", methods=["GET"])
def health():
    """
    Healthcheck endpoint to verify server and model status.
    """
    model_exists = os.path.exists(os.path.join(os.path.dirname(__file__), "model", "phishing_model.pkl"))
    return jsonify({
        "status": "healthy",
        "model_loaded": model_exists
    }), 200


if __name__ == "__main__":
    print("=" * 60)
    print("  PHISHING WEBSITE DETECTION SYSTEM - FLASK SERVER")
    print("  Accessible at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True, use_reloader=False)
