# 🛡️ 02 - Phishing URL Detector

A machine learning-based web application that classifies URLs as **phishing** or **legitimate** by analyzing key URL features — built with Python, Scikit-learn, and Flask.

## 🔍 About
Phishing attacks trick users by mimicking real websites. This project uses ML to detect suspicious URLs based on features like HTTPS usage, anchor tags, domain patterns, and more — helping users stay safe before clicking any link.

## 🚀 Tech Stack
- **Language:** Python
- **ML Library:** Scikit-learn
- **Web Framework:** Flask
- **Data Analysis:** Pandas, NumPy

## ⚙️ Features
- URL feature extraction (HTTPS, anchor tags, domain info)
- ML model trained to classify phishing vs legitimate
- Flask web interface for real-time URL checking

## 📦 Installation
```bash
git clone https://github.com/akshaykumarsatyala/02-phishing-url-detector.git
cd 02-phishing-url-detector
pip install -r requirements.txt
python app.py
```

## 🧠 ML Model
Trained using Scikit-learn classifiers on phishing datasets. Key features analyzed: HTTPS presence, AnchorURL ratio, WebsiteTraffic, domain age, and more.

## 👨‍💻 Author
**Akshay Kumar Satyala** — [GitHub](https://github.com/akshaykumarsatyala)
