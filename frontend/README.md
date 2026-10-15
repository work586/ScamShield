# 🛡️ ScamShield - AI-Powered Multichannel Scam Detection System

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Django](https://img.shields.io/badge/Django-5.x-success)
![React](https://img.shields.io/badge/React-19-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 📖 Overview

ScamShield is an AI-powered multichannel scam detection system designed to identify and classify fraudulent communications across multiple platforms in real time. It continuously monitors SMS, WhatsApp notifications, emails, Telegram messages, incoming calls, and voice recordings to detect phishing attempts, OTP theft, bank fraud, impersonation, investment scams, romance scams, job scams, and other cyber threats.

The system combines Natural Language Processing (NLP), Machine Learning, rule-based analysis, URL safety detection, and phone number analysis to generate a risk score and provide users with real-time scam alerts through an interactive React dashboard.

---

# ✨ Features

- 📱 Automatic SMS Scam Detection
- 💬 WhatsApp Notification Scam Detection
- 📧 Email Scam Detection
- ✈️ Telegram Personal Message Detection
- 📞 Incoming Call Monitoring
- 🎤 Voice Recording Analysis
- 🤖 AI-Based Scam Classification
- 🌐 Multilingual Detection
  - English
  - Hindi
  - Hinglish
  - Kannada
- 🔗 Suspicious URL Detection
- ☎️ Phone Number Analysis
- 📊 AI Risk Score (0–100)
- 📂 Complete Scan History
- 📈 Interactive React Dashboard
- ⚡ Real-Time Monitoring
- 👨‍💼 Django Super Admin Panel

---

# 🧠 Scam Categories Detected

ScamShield can identify:

- OTP Theft
- Bank Fraud
- Phishing
- Lottery Scam
- Investment Scam
- Romance Scam
- Job Scam
- Government Impersonation
- Customer Care Fraud
- Fake Delivery Scam
- Social Engineering
- Loan Scam
- Cryptocurrency Scam

---

# 🌐 Supported Platforms

| Platform | Status | Implementation |
|----------|--------|----------------|
| SMS | ✅ | MacroDroid |
| WhatsApp Notifications | ✅ | MacroDroid |
| Incoming Calls | ✅ | MacroDroid |
| Email | ✅ | Gmail IMAP |
| Telegram | ✅ | Pyrogram |
| Voice Recording | ✅ | SpeechRecognition |

---

# 🏗️ System Architecture

```text
                     Incoming Communication

 SMS     WhatsApp     Calls     Email     Telegram     Voice
  │          │           │          │           │          │
  │          │           │          │           │          │
  └────── MacroDroid ────┘      Gmail IMAP   Pyrogram     │
                │                    │            │        │
                └────────────┬───────┴────────────┴────────┘
                             │
                     Django REST Framework API
                             │
                             ▼
                  ScamShield AI Detection Engine
 ┌──────────────────────────────────────────────────────────────┐
 │ Text Preprocessing                                            │
 │ Language Detection                                            │
 │ NLP Analysis                                                  │
 │ Machine Learning Classification                               │
 │ Scam Keyword Detection                                        │
 │ URL Safety Analysis                                           │
 │ Phone Number Analysis                                         │
 │ Risk Score Generation                                         │
 │ Scam Category Classification                                  │
 └──────────────────────────────────────────────────────────────┘
                             │
                             ▼
                      SQLite Database
                             │
                             ▼
               React Dashboard & Django Admin
```

---

# ⚙️ Detection Workflow

## SMS Detection

```text
Incoming SMS
      │
MacroDroid
      │
HTTP Request
      │
Django API
      │
AI Engine
      │
SQLite Database
      │
React Dashboard
```

---

## WhatsApp Detection

```text
WhatsApp Notification
         │
MacroDroid
         │
HTTP Request
         │
Django API
         │
AI Engine
         │
Dashboard
```

---

## Incoming Call Detection

```text
Incoming Call
      │
MacroDroid
      │
Caller Details
      │
Django API
      │
AI Engine
      │
Dashboard
```

---

## Email Detection

```text
Incoming Email
      │
Gmail IMAP
      │
Email Parser
      │
Django API
      │
AI Engine
      │
Dashboard
```

---

## Telegram Detection

```text
Incoming Telegram Message
            │
Pyrogram Client
            │
Webhook
            │
Django API
            │
AI Engine
            │
Dashboard
```

---

# 👨‍💼 Super Admin Panel

ScamShield includes a secure Django Super Admin Panel that allows administrators to monitor and manage all scam detection activities through a centralized interface.

### Super Admin Features

- 🔐 Secure Authentication
- 👤 Admin User Management
- 📊 View Complete Scan History
- 📱 Monitor SMS Detection
- 💬 Monitor WhatsApp Detection
- 📧 Monitor Email Detection
- ✈️ Monitor Telegram Messages
- 📞 Monitor Incoming Calls
- 🎤 View Voice Analysis Results
- 📈 Monitor Risk Scores
- 🚨 Review Scam Categories
- 🔍 Search & Filter Detection Records
- 🗑️ Manage Detection Records
- 💾 Database Administration

---

# 🛠️ Technology Stack

## Backend

- Python
- Django
- Django REST Framework

## Frontend

- React.js
- HTML5
- CSS3
- JavaScript

## AI & NLP

- Scikit-learn
- NLTK
- Regular Expressions
- Pickle
- SpeechRecognition

## Automation

- MacroDroid
- Gmail IMAP
- Pyrogram

## Database

- SQLite3

---

# 📂 Project Structure

```text
ScamShield/
│
├── backend/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── detector/
│   ├── migrations/
│   ├── admin.py
│   ├── ai_engine.py
│   ├── apps.py
│   ├── models.py
│   ├── urls.py
│   └── views.py
│
├── frontend/
│   ├── public/
│   ├── src/
│   ├── package.json
│   └── node_modules/
│
├── data/
├── auto_interceptor.py
├── telegram_personal.py
├── train_model.py
├── test_imap.py
├── requirements.txt
├── manage.py
└── README.md
```

---

# 🧠 AI Detection Pipeline

The ScamShield AI Engine performs the following operations:

1. Text Cleaning
2. Language Detection
3. URL Analysis
4. Phone Number Analysis
5. Scam Keyword Detection
6. Machine Learning Prediction
7. Risk Score Calculation
8. Scam Category Classification
9. Store Detection History

---

# 📊 Risk Score

| Risk Score | Status |
|------------|--------|
| 0 – 29 | ✅ Safe |
| 30 – 59 | ⚠️ Suspicious |
| 60 – 100 | 🚨 High Risk |

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/ScamShield.git

cd ScamShield
```

---

## Create Virtual Environment

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Apply Database Migrations

```bash
python manage.py migrate
```

---

## Create Django Super Admin

```bash
python manage.py createsuperuser
```

Enter:

```text
Username:
Email Address:
Password:
Confirm Password:
```

---

## Run Django Server

```bash
python manage.py runserver 0.0.0.0:8000
```

---

## Run React Application

```bash
cd frontend

npm install

npm start
```

---

## Start Email Monitoring

```bash
python auto_interceptor.py
```

---



---

## Train Machine Learning Model (Optional)

```bash
python train_model.py
```

---

# 🔑 Access Django Admin

After creating a superuser, open:

```
http://127.0.0.1:8000/admin/
```

or

```
http://<YOUR_LOCAL_IP>:8000/admin/
```

Log in using your Django Super Admin credentials.

---

# 📡 API Endpoints

| Method | Endpoint | Description |
|---------|----------|-------------|
| POST | `/api/analyze/` | Analyze Text |
| POST | `/api/sms-webhook/` | SMS / WhatsApp / Call Webhook |
| POST | `/api/auto-scan/` | Email Detection |
| POST | `/api/voice/` | Voice Analysis |
| GET | `/api/history/` | Scan History |

---

# 📊 Dashboard

The React Dashboard provides:

- 📈 Live Scam Detection
- 📂 Complete Scan History
- 📊 Risk Score Visualization
- 🚨 Scam Category
- 🌐 Detected Language
- 📱 Communication Channel
- 🕒 Detection Timestamp
- 🔍 Search & Filter Records

---

# 🔮 Future Enhancements

- Android Companion App
- WhatsApp Business API Integration
- Live Voice Call Transcription
- Browser Extension
- QR Code Scam Detection
- OCR Image Scam Detection
- URL Reputation API Integration
- User Authentication
- Cloud Deployment
- Analytics Dashboard
- Mobile Application

---

# ⚠️ Disclaimer

ScamShield is developed for educational and research purposes only.

The system is designed to assist users in identifying potentially fraudulent communications and should not be considered a replacement for professional cybersecurity solutions or official fraud prevention services.

---

# 👩‍💻 Developed By

**ScamShield Team**

AI-Powered Multichannel Scam Detection System using **Python, Django, React, Machine Learning, NLP, MacroDroid, Gmail IMAP, and Pyrogram**.