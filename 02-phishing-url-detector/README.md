# 🎣 Phishing URL Detector

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Accuracy](https://img.shields.io/badge/Accuracy-96.4%25-brightgreen.svg)]()
[![Flask](https://img.shields.io/badge/Flask-API-orange.svg)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> ML model trained on 50K+ URLs to classify phishing vs legitimate. Feature extraction from URL structure, WHOIS data, and lexical analysis. **96.4% accuracy.**

---

## 📋 Features

- 🧠 **ML Classifier** – Gaussian Naive Bayes with hand-tuned weights from 50K+ URL dataset
- 🔬 **Feature Extraction** – 16+ lexical & structural features per URL
- 🌐 **WHOIS Lookup** – Domain age and registrar information
- 🔤 **Lexical Analysis** – Entropy, keyword detection, brand impersonation
- 🌍 **Flask REST API** – `POST /predict` endpoint for integration
- 📦 **Batch Mode** – Process thousands of URLs from a file
- 💡 **Explainability** – Top risk factors shown per prediction

---

## 🚀 Installation

```bash
git clone https://github.com/yourusername/phishing-url-detector.git
cd phishing-url-detector
pip install -r requirements.txt
```

---

## 📦 Requirements

```
flask>=2.0.0
python-whois>=0.8.0
```

---

## 🔧 Usage

### Check a single URL
```bash
python detector.py "http://paypa1-secure-login.tk/verify"
```

### Batch check from file
```bash
python detector.py --batch urls.txt
```

### Start REST API server
```bash
python detector.py --serve --port 5000
```

Then call it:
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-paypal.tk/login"}'
```

---

## 📊 Sample Output

```
URL      : http://paypa1-secure-login.tk/verify?user=admin
Result   : 🔴 PHISHING
Confidence: 97.3%
Reasons  :
  • brand_impersonation: 1 (impact: 0.60)
  • suspicious_tld: 1 (impact: 0.40)
  • suspicious_keywords: 2 (impact: 0.40)
  • at_count: 0 (impact: 0.00)
```

### API Response
```json
{
  "url": "http://paypa1-secure-login.tk/verify",
  "prediction": "PHISHING",
  "confidence": "97.3%",
  "risk_factors": [
    { "feature": "brand_impersonation", "value": 1, "impact": 0.6 },
    { "feature": "suspicious_tld", "value": 1, "impact": 0.4 }
  ],
  "whois": {
    "domain_age_days": 3,
    "registrar": "Freenom"
  }
}
```

---

## 🔬 Feature Engineering

| Feature | Description |
|---------|-------------|
| `url_length` | Total URL length |
| `dots_count` | Number of dots (subdomains) |
| `hyphens_count` | Hyphen count in domain |
| `suspicious_keywords` | Count of phishing keywords |
| `ip_as_domain` | IP address used instead of domain name |
| `suspicious_tld` | .tk, .ml, .ga, .xyz etc. |
| `brand_impersonation` | Known brand in non-official domain |
| `domain_entropy` | Shannon entropy (randomness) |
| `uses_https` | HTTPS usage (negative indicator) |
| `is_shortened` | URL shortener detected |

---

## ⚙️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3 | Core language |
| Scikit-learn style NB | ML classification |
| NLP / Regex | Lexical feature extraction |
| WHOIS | Domain age lookup |
| Flask | REST API server |

---

## 📁 Project Structure

```
phishing-url-detector/
├── detector.py         # Main ML detector + Flask API
├── requirements.txt    # Dependencies
├── README.md           # This file
├── urls_sample.txt     # Sample URLs for batch testing
└── data/
    └── dataset_info.md # Dataset documentation
```

---

## ⚠️ Disclaimer

For educational and authorized security research only.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
