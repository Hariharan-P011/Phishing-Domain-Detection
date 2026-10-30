import os
import sys
from API import get_prediction

# Locate model dynamically relative to this script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "models", "Malicious_URL_Prediction.h5")

# URL to test (can be passed via command line argument or use default)
url = sys.argv[1] if len(sys.argv) > 1 else "www.tesla.com/"

print(f"Testing URL: {url}")
print(f"Model Path:  {model_path}")
print("-" * 50)

# Returns probability of URL being malicious
prediction = get_prediction(url, model_path)
print("-" * 50)
print(f"Final Prediction: {prediction}% malicious probability")
if prediction >= 50:
    print("Verdict: [DANGER] Malicious / Phishing URL detected!")
else:
    print("Verdict: [SAFE] URL is legitimate.")
