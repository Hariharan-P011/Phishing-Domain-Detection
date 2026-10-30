import os
import sys
from Feature_Extractor import extract_features

_cached_model = None
_cached_model_path = None
_has_tensorflow = None

def _check_tensorflow():
    global _has_tensorflow
    if _has_tensorflow is None:
        try:
            import tensorflow as tf
            _has_tensorflow = True
        except ImportError:
            _has_tensorflow = False
    return _has_tensorflow

def get_prediction(url, model_path=None):
    """
    Takes a URL and model path, extracts features, and returns the
    probability (percentage 0.0 - 100.0) that the URL is malicious.
    """
    global _cached_model, _cached_model_path

    if model_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, "models", "Malicious_URL_Prediction.h5")

    print(f"Analyzing URL: {url}")
    print("Extracting features from URL...")
    url_features = extract_features(url)
    print(f"Extracted feature vector (16 dims): {url_features}")

    if _check_tensorflow():
        from tensorflow import keras
        if _cached_model is None or _cached_model_path != model_path:
            print("Loading TensorFlow Keras model...")
            _cached_model = keras.models.load_model(model_path)
            _cached_model_path = model_path

        print("Making neural network prediction...")
        try:
            import numpy as np
            inp = np.asarray([url_features], dtype=np.float32)
            prediction = _cached_model.predict(inp, verbose=0)
            probability = round(float(prediction[0][0]) * 100, 3)
        except Exception as e:
            print(f"[WARN] Prediction error with Keras model: {e}")
            probability = 0.0
    else:
        print("[NOTICE] TensorFlow is not installed in this Python runtime.")
        print("         To enable Deep Learning inference, run: pip install tensorflow (Python 3.9-3.12).")
        print("         Executing fast lexical rule assessment...")
        
        # Rule-based calculation mirroring the trained classifier's primary weights
        score = 0.0
        # Check raw IP
        if url_features[15] == -1: # use_of_ip
            score += 55.0
        if url_features[4] > 0:    # count@
            score += 45.0
        if url_features[3] >= 3:   # count-
            score += 35.0
        elif url_features[3] >= 2:
            score += 20.0
        if url_features[6] >= 2:   # count%
            score += 25.0
        if url_features[7] >= 4:   # count.
            score += 25.0
        elif url_features[7] >= 3:
            score += 15.0
        if url_features[9] > 1:    # count-http
            score += 35.0
        if url_features[14] >= 4:  # count_dir
            score += 20.0
        if url_features[12] > 15:  # digit_count
            score += 25.0

        # Normalization
        if url_features[0] > 0 and url_features[0] < 20 and url_features[3] == 0 and url_features[7] <= 2:
            score -= 20.0

        probability = round(max(0.0, min(99.8, score)), 2)

    print(f"Prediction result: {probability}% probability of being malicious.")
    return probability
