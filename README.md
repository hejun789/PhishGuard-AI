# PhishGuard AI — ML Phishing URL Detection System

A full-stack machine learning application that detects phishing URLs in real time.  
Built with Python, scikit-learn, and Flask — cyberpunk dark UI.

---

## Features

- **6,000-sample synthetic dataset** — 3,000 legitimate + 3,000 phishing URLs
- **24 extracted URL features** — entropy, suspicious keywords, TLD, subdomains, special chars, and more
- **4 ML models trained & compared** — Random Forest, Gradient Boosting, Logistic Regression, SVM
- **Evaluation charts** — model comparison, ROC curves, confusion matrix, feature importance
- **REST API** — `POST /api/predict` returns prediction, confidence, and risk factors
- **Cyberpunk UI** — matrix rain background, glitch title, neon glow, animated results

---

## Tech Stack

| Layer       | Technology                                    |
|-------------|-----------------------------------------------|
| ML          | scikit-learn, pandas, numpy                   |
| Visualization | matplotlib, seaborn                         |
| Backend     | Flask 3.x                                     |
| Frontend    | HTML5, CSS3 (custom properties + animations), Vanilla JS |
| Language    | Python 3.10+                                  |

---

## Project Structure

```
PhishGuard-AI/
├── data/
│   ├── generate_dataset.py   # Synthetic dataset generator
│   └── dataset.csv           # Generated (not tracked in git)
├── models/
│   ├── train_models.py       # Train, evaluate, save models
│   ├── phishguard_model.pkl  # Best saved model (not tracked)
│   ├── scaler.pkl            # Feature scaler
│   └── model_info.pkl        # Model metadata
├── static/
│   ├── css/style.css         # Cyberpunk dark theme
│   ├── js/app.js             # Frontend logic + matrix rain
│   └── images/               # Generated evaluation charts
├── templates/
│   └── index.html            # Main UI
├── app.py                    # Flask application
├── feature_extractor.py      # 24-feature URL parser
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate dataset

```bash
python data/generate_dataset.py
```

Outputs `data/dataset.csv` — 6,000 labelled URLs with 24 extracted features.

### 3. Train models

```bash
python models/train_models.py
```

Trains all 4 models, selects the best by F1-score, saves to `models/`, and writes charts to `static/images/`.

### 4. Launch the app

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

---

## 24 URL Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | `url_length` | Total URL character count |
| 2 | `domain_length` | Domain name character count |
| 3 | `has_ip` | IP address used instead of domain name |
| 4 | `is_https` | Uses HTTPS (secure) protocol |
| 5 | `num_dots` | Count of `.` characters |
| 6 | `num_hyphens` | Count of `-` characters |
| 7 | `num_underscores` | Count of `_` characters |
| 8 | `num_slashes` | Count of `/` characters |
| 9 | `num_at` | `@` symbol present (credential trick) |
| 10 | `num_ampersand` | Count of `&` characters |
| 11 | `num_question` | Count of `?` characters |
| 12 | `num_equal` | Count of `=` characters |
| 13 | `num_digits_in_domain` | Digit count in domain |
| 14 | `suspicious_keywords` | Count of suspicious words (login, verify, secure…) |
| 15 | `suspicious_tld` | Uses suspicious TLD (.tk, .ml, .xyz…) |
| 16 | `has_subdomain` | Has subdomain |
| 17 | `subdomain_length` | Character count of subdomain |
| 18 | `path_length` | URL path character count |
| 19 | `query_length` | Query string character count |
| 20 | `url_entropy` | Shannon entropy (high = obfuscated) |
| 21 | `brand_in_path` | Known brand name appears in path (not domain) |
| 22 | `has_port` | Non-standard port specified |
| 23 | `special_char_ratio` | Ratio of unusual special characters |
| 24 | `double_slash` | Double-slash redirect trick |

---

## API Reference

### `POST /api/predict`

**Request**
```json
{ "url": "https://example.com" }
```

**Response**
```json
{
  "url": "https://example.com",
  "prediction": "legitimate",
  "confidence": 0.9823,
  "risk_score": 0,
  "risk_factors": [],
  "features": { "url_length": 23, "is_https": 1, ... },
  "model": "Gradient Boosting"
}
```

### `GET /api/health`

Returns model status.

---

## Model Performance (typical)

| Model | Accuracy | F1-Score |
|-------|----------|----------|
| **Gradient Boosting** | ~0.98 | ~0.98 |
| **Random Forest** | ~0.97 | ~0.97 |
| Logistic Regression | ~0.93 | ~0.93 |
| SVM | ~0.95 | ~0.95 |

*Results vary slightly per run due to synthetic data randomness.*

---

## Phishing Detection Strategies Modelled

- **IP-based URLs** — `http://192.168.1.1/paypal/login.php`
- **Suspicious TLD** — `paypal-verify.tk`
- **Subdomain abuse** — `paypal.verify-account.com`
- **Lookalike domains** — `paypa1.com`, `g00gle.com`
- **@ trick** — `paypal.com@attacker.com/signin`
- **Long URL obfuscation** — 150+ character URLs with token parameters
- **Brand-in-path injection** — `evil.xyz/paypal/login.php`

---

## License

MIT — Free to use for educational and portfolio purposes.
