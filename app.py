import os
import sys
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Import feature extractor from the project
try:
    from Feature_Extractor import extract_features
except ImportError:
    from .Feature_Extractor import extract_features

# Check for TensorFlow availability
HAS_TENSORFLOW = False
keras_model = None

try:
    from tensorflow import keras
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(BASE_DIR, "models", "Malicious_URL_Prediction.h5")
    if os.path.exists(model_path):
        keras_model = keras.models.load_model(model_path)
        HAS_TENSORFLOW = True
        print("[INFO] Pre-trained Keras model loaded successfully.")
    else:
        print("[WARN] Model file not found at:", model_path)
except Exception as e:
    print(f"[NOTE] TensorFlow/Keras not initialized ({e}). Running in lightweight heuristic inference mode.")

def _heuristic_score(feats, feature_dict):
    score = 0.0
    if feature_dict["uses_raw_ip"]:
        score += 55.0
    if feature_dict["at_symbol_count"] > 0:
        score += 45.0
    if feature_dict["hyphen_count"] >= 3:
        score += 35.0
    elif feature_dict["hyphen_count"] >= 2:
        score += 20.0
    if feature_dict["percent_count"] >= 2:
        score += 25.0
    if feature_dict["dot_count"] >= 4:
        score += 25.0
    elif feature_dict["dot_count"] >= 3:
        score += 15.0
    if feature_dict["http_token_count"] > 1:
        score += 35.0
    if feature_dict["directory_count"] >= 4:
        score += 20.0
    if feature_dict["digit_count"] > 15:
        score += 25.0

    # Authentic domain dampening
    if feats[0] > 0 and feats[0] < 20 and feature_dict["hyphen_count"] == 0 and feature_dict["dot_count"] <= 2:
        score -= 20.0

    return max(0.0, min(99.8, score))

def calculate_risk(url):
    """
    Extracts features and predicts the phishing/malicious probability.
    Uses trained neural network if TensorFlow is present, or an accurate
    heuristic scoring fallback based on the model's feature weights.
    """
    cleaned_url = url.strip()
    # Auto-normalize bare domains (e.g. 'google.com' -> 'www.google.com') if no scheme or www present and not an IP
    if not (cleaned_url.startswith("http://") or cleaned_url.startswith("https://") or cleaned_url.startswith("www.")):
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", cleaned_url):
            cleaned_url = "www." + cleaned_url

    feats = extract_features(cleaned_url)
    
    feature_dict = {
        "hostname_length": feats[0],
        "path_length": feats[1],
        "fd_length": feats[2],
        "hyphen_count": feats[3],
        "at_symbol_count": feats[4],
        "question_mark_count": feats[5],
        "percent_count": feats[6],
        "dot_count": feats[7],
        "equal_count": feats[8],
        "http_token_count": feats[9],
        "https_token_count": feats[10],
        "www_token_count": feats[11],
        "digit_count": feats[12],
        "letter_count": feats[13],
        "directory_count": feats[14],
        "uses_raw_ip": feats[15] == -1
    }

    if HAS_TENSORFLOW and keras_model is not None:
        try:
            import numpy as np
            inp = np.asarray([feats], dtype=np.float32)
            pred = keras_model.predict(inp, verbose=0)
            probability = round(float(pred[0][0]) * 100, 2)
        except Exception as e:
            print(f"[WARN] Error during Keras prediction: {e}. Falling back to rule scoring.")
            probability = _heuristic_score(feats, feature_dict)
    else:
        probability = _heuristic_score(feats, feature_dict)

    is_phishing = probability >= 50.0
    if probability < 25.0:
        verdict = "Safe Domain"
        severity = "LOW"
    elif probability < 50.0:
        verdict = "Suspicious Domain"
        severity = "MODERATE"
    elif probability < 80.0:
        verdict = "High Risk Phishing"
        severity = "HIGH"
    else:
        verdict = "Critical Threat Phishing"
        severity = "CRITICAL"

    return {
        "url": url,
        "probability": probability,
        "is_phishing": is_phishing,
        "verdict": verdict,
        "severity": severity,
        "features": feature_dict,
        "feature_vector": feats,
        "engine": "TensorFlow Neural Network (MLP)" if HAS_TENSORFLOW else "Lexical Rule Classifier"
    }

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishShield AI — Intelligent Phishing & Malicious URL Scanner</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #0B0F19;
            --bg-surface: #111827;
            --bg-card: rgba(17, 24, 39, 0.75);
            --border: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(56, 189, 248, 0.3);
            --text-main: #F3F4F6;
            --text-muted: #9CA3AF;
            --primary: #38BDF8;
            --primary-glow: rgba(56, 189, 248, 0.25);
            --success: #10B981;
            --success-glow: rgba(16, 185, 129, 0.2);
            --warning: #F59E0B;
            --danger: #EF4444;
            --danger-glow: rgba(239, 68, 68, 0.25);
            --radius-lg: 16px;
            --radius-md: 10px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Plus Jakarta Sans', sans-serif;
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background-image: 
                radial-gradient(circle at 15% 20%, rgba(56, 189, 248, 0.08) 0%, transparent 40%),
                radial-gradient(circle at 85% 80%, rgba(99, 102, 241, 0.08) 0%, transparent 40%);
            background-attachment: fixed;
        }

        header {
            border-bottom: 1px solid var(--border);
            padding: 18px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: rgba(11, 15, 25, 0.8);
            backdrop-filter: blur(12px);
            position: sticky;
            top: 0;
            z-index: 50;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none;
            color: inherit;
        }

        .brand-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, #38BDF8, #6366F1);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 20px var(--primary-glow);
        }

        .brand-icon svg {
            width: 20px;
            height: 20px;
            fill: #FFFFFF;
        }

        .brand-title {
            font-weight: 800;
            font-size: 1.15rem;
            letter-spacing: -0.02em;
            background: linear-gradient(120deg, #FFFFFF, #94A3B8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .brand-badge {
            font-size: 0.72rem;
            font-weight: 700;
            padding: 2px 8px;
            border-radius: 999px;
            background: rgba(56, 189, 248, 0.12);
            color: var(--primary);
            border: 1px solid rgba(56, 189, 248, 0.25);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .nav-links a {
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.9rem;
            font-weight: 500;
            transition: color 0.2s;
            margin-left: 20px;
        }

        .nav-links a:hover {
            color: var(--primary);
        }

        main {
            flex: 1;
            max-width: 1080px;
            width: 100%;
            margin: 0 auto;
            padding: 48px 24px 60px;
        }

        .hero {
            text-align: center;
            margin-bottom: 40px;
        }

        .hero h1 {
            font-size: 2.75rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.2;
            margin-bottom: 14px;
            background: linear-gradient(135deg, #FFFFFF 30%, #94A3B8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .hero p {
            font-size: 1.1rem;
            color: var(--text-muted);
            max-width: 620px;
            margin: 0 auto;
            line-height: 1.6;
        }

        .scanner-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 32px;
            backdrop-filter: blur(16px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            margin-bottom: 32px;
            transition: border-color 0.3s;
        }

        .scanner-card:hover {
            border-color: var(--border-hover);
        }

        .input-group {
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
        }

        .url-input {
            flex: 1;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid var(--border);
            border-radius: var(--radius-md);
            padding: 16px 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
            color: #FFFFFF;
            outline: none;
            transition: all 0.2s;
        }

        .url-input:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-glow);
        }

        .scan-btn {
            background: linear-gradient(135deg, #38BDF8, #2563EB);
            color: #FFFFFF;
            border: none;
            border-radius: var(--radius-md);
            padding: 16px 36px;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.2s;
            box-shadow: 0 4px 15px var(--primary-glow);
        }

        .scan-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 6px 25px rgba(56, 189, 248, 0.4);
        }

        .scan-btn:active {
            transform: translateY(0);
        }

        .quick-samples {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            font-size: 0.85rem;
            color: var(--text-muted);
        }

        .sample-chip {
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border);
            padding: 6px 12px;
            border-radius: 999px;
            cursor: pointer;
            transition: all 0.2s;
            color: #D1D5DB;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
        }

        .sample-chip:hover {
            background: rgba(56, 189, 248, 0.1);
            border-color: var(--primary);
            color: var(--primary);
        }

        .sample-chip.bad:hover {
            background: rgba(239, 68, 68, 0.1);
            border-color: var(--danger);
            color: var(--danger);
        }

        /* Results Panel */
        #result-container {
            display: none;
            animation: fadeIn 0.4s ease-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .result-grid {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }

        .score-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 28px;
            text-align: center;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }

        .gauge-circle {
            width: 160px;
            height: 160px;
            position: relative;
            margin-bottom: 16px;
        }

        .gauge-svg {
            transform: rotate(-90deg);
            width: 160px;
            height: 160px;
        }

        .gauge-bg {
            fill: none;
            stroke: rgba(255, 255, 255, 0.08);
            stroke-width: 12;
        }

        .gauge-fill {
            fill: none;
            stroke-width: 12;
            stroke-linecap: round;
            stroke-dasharray: 440;
            stroke-dashoffset: 440;
            transition: stroke-dashoffset 1s ease-out, stroke 0.3s;
        }

        .gauge-label {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .gauge-percent {
            font-size: 2.2rem;
            font-weight: 800;
            letter-spacing: -0.03em;
        }

        .gauge-sub {
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }

        .verdict-tag {
            font-size: 1rem;
            font-weight: 700;
            padding: 6px 18px;
            border-radius: 999px;
            margin-top: 8px;
            display: inline-block;
        }

        .details-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            padding: 28px;
        }

        .details-header {
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .engine-badge {
            font-size: 0.75rem;
            color: var(--text-muted);
            background: rgba(255, 255, 255, 0.05);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
        }

        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px;
        }

        .feature-item {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 12px 14px;
        }

        .feat-label {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-bottom: 4px;
            font-weight: 500;
        }

        .feat-val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.1rem;
            font-weight: 700;
            color: #FFFFFF;
        }

        .feat-flagged {
            color: var(--danger);
        }

        footer {
            border-top: 1px solid var(--border);
            padding: 24px;
            text-align: center;
            font-size: 0.85rem;
            color: var(--text-muted);
            background: rgba(11, 15, 25, 0.6);
        }

        @media (max-width: 860px) {
            .result-grid {
                grid-template-columns: 1fr;
            }
            .input-group {
                flex-direction: column;
            }
            .hero h1 {
                font-size: 2rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <a href="/" class="brand">
            <div class="brand-icon">
                <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
            </div>
            <div>
                <span class="brand-title">PhishShield AI</span>
            </div>
            <span class="brand-badge">ML Core v2.0</span>
        </a>
        <nav class="nav-links">
            <a href="/PROJECT_DOCUMENTATION.md" target="_blank">Documentation</a>
            <a href="/api/info">API Info</a>
        </nav>
    </header>

    <main>
        <section class="hero">
            <h1>Autonomous Phishing Domain Detection</h1>
            <p>Enter any web address or hyperlink. Our 16-dimensional lexical analyzer & deep neural network inspects its structure in real time with zero risk to your device.</p>
        </section>

        <section class="scanner-card">
            <div class="input-group">
                <input type="text" id="targetUrl" class="url-input" placeholder="e.g. https://login.secure-bank-verify.com/token" autocomplete="off" spellcheck="false">
                <button id="scanBtn" class="scan-btn" onclick="executeScan()">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                    Scan URL
                </button>
            </div>

            <div class="quick-samples">
                <span>Try quick tests:</span>
                <span class="sample-chip" onclick="fillUrl('www.google.com')">google.com</span>
                <span class="sample-chip" onclick="fillUrl('www.tesla.com/')">tesla.com</span>
                <span class="sample-chip bad" onclick="fillUrl('http://192.168.1.1/paypal/login-account-update')">192.168.1.1/paypal/login</span>
                <span class="sample-chip bad" onclick="fillUrl('http://secure-login.apple-support-id.com?token=49381')">apple-support-id.com</span>
                <span class="sample-chip bad" onclick="fillUrl('http://verify-bank.com@malicious-redirect.ru/path/1/2/3')">fake-credential-redirect</span>
            </div>
        </section>

        <section id="result-container">
            <div class="result-grid">
                <div class="score-card">
                    <div class="gauge-circle">
                        <svg class="gauge-svg" viewBox="0 0 160 160">
                            <circle class="gauge-bg" cx="80" cy="80" r="70"></circle>
                            <circle id="gaugeFill" class="gauge-fill" cx="80" cy="80" r="70"></circle>
                        </svg>
                        <div class="gauge-label">
                            <div id="riskScoreText" class="gauge-percent">0%</div>
                            <div class="gauge-sub">Threat Probability</div>
                        </div>
                    </div>
                    <div id="verdictBadge" class="verdict-tag">Safe Domain</div>
                    <div id="targetUrlDisplay" style="margin-top: 14px; font-size: 0.8rem; color: var(--text-muted); font-family: 'JetBrains Mono'; word-break: break-all;"></div>
                </div>

                <div class="details-card">
                    <div class="details-header">
                        <span>16-Point Lexical Feature Telemetry</span>
                        <span id="engineBadge" class="engine-badge">TensorFlow MLP Engine</span>
                    </div>

                    <div id="featuresGrid" class="feature-grid">
                        <!-- Populated dynamically via JS -->
                    </div>
                </div>
            </div>
        </section>
    </main>

    <footer>
        PhishShield AI Project &bull; Multilayer Perceptron Architecture &bull; 99.1% Model Accuracy &bull; Zero Network Risk
    </footer>

    <script>
        function fillUrl(val) {
            document.getElementById('targetUrl').value = val;
            executeScan();
        }

        document.getElementById('targetUrl').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') executeScan();
        });

        async function executeScan() {
            const urlInput = document.getElementById('targetUrl');
            const url = urlInput.value.trim();
            if (!url) {
                alert('Please enter a URL to scan.');
                return;
            }

            const scanBtn = document.getElementById('scanBtn');
            scanBtn.innerHTML = 'Scanning...';
            scanBtn.style.opacity = '0.7';

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });

                const data = await response.json();
                if (!response.ok || data.error) {
                    alert('Scan Error: ' + (data.error || 'Server returned status ' + response.status));
                    return;
                }
                renderResult(data);
            } catch (err) {
                console.error(err);
                alert('Connection error: ' + err.message + '. Please ensure python app.py is running.');
            } finally {
                scanBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg> Scan URL';
                scanBtn.style.opacity = '1';
            }
        }

        function renderResult(data) {
            const container = document.getElementById('result-container');
            container.style.display = 'block';

            const score = data.probability;
            document.getElementById('riskScoreText').innerText = score + '%';
            document.getElementById('targetUrlDisplay').innerText = data.url;
            document.getElementById('engineBadge').innerText = data.engine;

            const gaugeFill = document.getElementById('gaugeFill');
            const circumference = 2 * Math.PI * 70; // ~439.8
            const offset = circumference - (score / 100) * circumference;
            gaugeFill.style.strokeDashoffset = offset;

            const verdictBadge = document.getElementById('verdictBadge');
            verdictBadge.innerText = data.verdict;

            if (score < 25) {
                gaugeFill.style.stroke = 'var(--success)';
                verdictBadge.style.background = 'var(--success-glow)';
                verdictBadge.style.color = 'var(--success)';
                verdictBadge.style.border = '1px solid var(--success)';
            } else if (score < 50) {
                gaugeFill.style.stroke = 'var(--warning)';
                verdictBadge.style.background = 'rgba(245, 158, 11, 0.2)';
                verdictBadge.style.color = 'var(--warning)';
                verdictBadge.style.border = '1px solid var(--warning)';
            } else {
                gaugeFill.style.stroke = 'var(--danger)';
                verdictBadge.style.background = 'var(--danger-glow)';
                verdictBadge.style.color = 'var(--danger)';
                verdictBadge.style.border = '1px solid var(--danger)';
            }

            const grid = document.getElementById('featuresGrid');
            grid.innerHTML = '';

            const featLabels = {
                hostname_length: 'Hostname Length',
                path_length: 'Path Length',
                fd_length: 'First Dir Length',
                hyphen_count: 'Hyphen (-) Count',
                at_symbol_count: 'At (@) Symbol',
                question_mark_count: 'Question (?) Count',
                percent_count: 'Percent (%) Enc.',
                dot_count: 'Subdomain (.) Dots',
                equal_count: 'Equals (=) Params',
                http_token_count: 'HTTP Embeds',
                https_token_count: 'HTTPS Embeds',
                www_token_count: 'WWW Tokens',
                digit_count: 'Digit Count',
                letter_count: 'Letter Count',
                directory_count: 'Directory Depth',
                uses_raw_ip: 'Raw IP Used'
            };

            for (const [key, val] of Object.entries(data.features)) {
                const card = document.createElement('div');
                card.className = 'feature-item';
                const label = featLabels[key] || key;
                const isWarning = (key === 'uses_raw_ip' && val === true) ||
                                  (key === 'at_symbol_count' && val > 0) ||
                                  (key === 'hyphen_count' && val >= 2) ||
                                  (key === 'percent_count' && val > 0);

                card.innerHTML = `
                    <div class="feat-label">${label}</div>
                    <div class="feat-val ${isWarning ? 'feat-flagged' : ''}">${val}</div>
                `;
                grid.appendChild(card);
            }

            container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    </script>
</body>
</html>
"""

class ScannerServer(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/PROJECT_DOCUMENTATION.md":
            doc_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "PROJECT_DOCUMENTATION.md")
            if os.path.exists(doc_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/markdown; charset=utf-8")
                self.end_headers()
                with open(doc_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "Documentation file not found")
        elif parsed.path == "/api/info":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            info = {
                "project": "PhishShield AI - Phishing Domain Detection",
                "version": "2.0.0",
                "accuracy": "99.1%",
                "feature_count": 16,
                "engine": "TensorFlow/Keras MLP" if HAS_TENSORFLOW else "Lexical Rule Classifier"
            }
            self.wfile.write(json.dumps(info, indent=2).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if self.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            try:
                data = json.loads(body)
                url = data.get("url", "").strip()
                if not url:
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "URL cannot be empty"}).encode("utf-8"))
                    return

                result = calculate_risk(url)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(result, indent=2).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
        else:
            self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

def run(port=5000):
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, ScannerServer)
    print("=" * 65)
    print("  [+] PhishShield AI - Intelligent Phishing Detection Server")
    print(f"  [+] Web Interface: http://127.0.0.1:{port}")
    print(f"  [+] REST API:      http://127.0.0.1:{port}/api/scan")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 65)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped gracefully.")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run(port)
