"""
PhishGuard AI — Flask backend.
Serves the frontend and exposes POST /api/predict.
"""

import os
import pickle
import numpy as np
from flask import Flask, request, jsonify, render_template

from feature_extractor import (
    extract_features, get_feature_names,
    SUSPICIOUS_KEYWORDS, SUSPICIOUS_TLDS, COMMON_BRANDS
)

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Model loading
# ---------------------------------------------------------------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')

_model       = None
_scaler      = None
_model_name  = 'Not loaded'
_needs_scale = False


def _load():
    global _model, _scaler, _model_name, _needs_scale
    model_path = os.path.join(MODEL_DIR, 'phishguard_model.pkl')
    scaler_path = os.path.join(MODEL_DIR, 'scaler.pkl')
    info_path   = os.path.join(MODEL_DIR, 'model_info.pkl')

    if not os.path.exists(model_path):
        raise FileNotFoundError(
            "Trained model not found. Run:  python models/train_models.py"
        )

    with open(model_path, 'rb') as f:
        _model = pickle.load(f)
    with open(scaler_path, 'rb') as f:
        _scaler = pickle.load(f)
    with open(info_path, 'rb') as f:
        info = pickle.load(f)

    _model_name  = info['name']
    _needs_scale = info['needs_scaling']
    print(f"[PhishGuard] Loaded model: {_model_name}  (scaling={_needs_scale})")


# ---------------------------------------------------------------------------
# Risk factor analysis
# ---------------------------------------------------------------------------
_RISK_RULES = [
    ('has_ip',           lambda v, _: v == 1,             'IP address used as domain'),
    ('is_https',         lambda v, _: v == 0,             'No HTTPS encryption'),
    ('suspicious_tld',   lambda v, _: v == 1,             'Suspicious domain extension'),
    ('num_at',           lambda v, _: v > 0,              '@ symbol in URL (credential trick)'),
    ('brand_in_path',    lambda v, _: v == 1,             'Brand name appears in path'),
    ('has_port',         lambda v, _: v == 1,             'Non-standard port specified'),
    ('double_slash',     lambda v, _: v == 1,             'Double-slash redirect detected'),
    ('suspicious_keywords', lambda v, _: v > 0,           lambda v, _: f'{v} suspicious keyword(s) found'),
    ('url_length',       lambda v, _: v > 100,            lambda v, _: f'Long URL ({v} chars)'),
    ('num_hyphens',      lambda v, _: v > 4,              lambda v, _: f'Excessive hyphens ({v})'),
    ('num_dots',         lambda v, _: v > 5,              lambda v, _: f'Too many dots ({v})'),
    ('has_subdomain',    lambda v, f: v == 1 and f.get('subdomain_length', 0) > 15,
                                                           'Unusually long subdomain'),
    ('url_entropy',      lambda v, _: v > 4.5,            lambda v, _: f'High URL entropy ({v:.2f})'),
    ('special_char_ratio', lambda v, _: v > 0.05,         lambda v, _: f'High special-char ratio ({v:.2%})'),
]


def _risk_factors(features):
    factors = []
    for key, condition, label in _RISK_RULES:
        val = features.get(key, 0)
        if condition(val, features):
            factors.append(label(val, features) if callable(label) else label)
    return factors


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/predict', methods=['POST'])
def predict():
    if _model is None:
        return jsonify({'error': 'Model not loaded. Train it first.'}), 503

    data = request.get_json(force=True, silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'JSON body with "url" field required'}), 400

    url = str(data['url']).strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400

    features     = extract_features(url)
    feat_names   = get_feature_names()
    feat_vector  = np.array([features[n] for n in feat_names], dtype=float).reshape(1, -1)

    X = _scaler.transform(feat_vector) if _needs_scale else feat_vector
    prediction   = int(_model.predict(X)[0])
    proba        = _model.predict_proba(X)[0]
    confidence   = float(max(proba))

    risk_factors = _risk_factors(features)
    risk_score   = len(risk_factors)

    return jsonify({
        'url'         : url,
        'prediction'  : 'phishing' if prediction == 1 else 'legitimate',
        'confidence'  : round(confidence, 4),
        'risk_score'  : risk_score,
        'risk_factors': risk_factors,
        'features'    : features,
        'model'       : _model_name,
    })


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status' : 'ok' if _model else 'no_model',
        'model'  : _model_name,
    })


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    _load()
    print("[PhishGuard] Starting server on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=False)
