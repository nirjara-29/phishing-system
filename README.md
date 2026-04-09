🛡️ Phishing URL & Email Detection Extension
📌 Overview

Phishing is one of the most widespread cyber threats in India, with thousands of malicious websites and emails targeting users every month.

This project builds a real-time phishing detection system that combines Machine Learning, a browser extension, and a scalable backend to detect and prevent phishing attacks before users interact with them.

🚨 Problem Statement

<<<<<<< HEAD
Students and senior citizens are especially vulnerable to phishing attacks. Cybercriminals create highly realistic emails and fake URLs to trick users into revealing sensitive information.
=======
Students and senior citizens are especially vulnerable to phishing attacks. Cybercriminals often create realistic-looking emails and fake URLs to trick users into revealing sensitive information.

The aim of the project is:
>>>>>>> d66b43c82202060b5d61e7011fa69acc387b54d9

The aim of this project is to:
Detect phishing URLs
Analyze suspicious email content and headers
Provide real-time alerts to users before any interaction
🎯 Objective

To protect everyday internet users from phishing attacks through intelligent, real-time threat detection integrated directly into their browsing and email experience.

🧠 Key Features
🔍 URL Analysis
Detects malicious patterns in URLs
Checks domain mismatch, length, HTTPS usage, and structure
📧 Email Scanner
Analyzes email headers and content
Identifies spoofed senders and phishing keywords
⚡ Real-Time Detection
Instant alerts before users click harmful links
Lightweight and fast processing
🧩 Browser Extension
Seamless integration with Chrome (Manifest V3)
Works in real-time while browsing
🤖 Machine Learning Detection
Classifies links/emails as:
✅ Safe
⚠️ Suspicious
❌ Phishing
🏗️ System Architecture

This project is built as a full-stack AI-powered system:

🔧 Backend
FastAPI (high-performance async APIs)
SQLAlchemy (async) + Alembic for DB migrations
Pydantic for validation
PostgreSQL-ready session handling
Structured logging with structlog
ML model handling using joblib
🤖 Machine Learning Pipeline
scikit-learn Pipeline
TfidfVectorizer + Logistic Regression
Additional Random Forest URL detector
CSV-based dataset ingestion
Python CSV fallback loader
Optional pandas-based data processing
Train/Test split with evaluation metrics
🌐 Frontend Web App
React + Vite
Zustand (state management)
Axios (API communication)
Tailwind CSS (UI styling)
react-hot-toast (notifications)
lucide-react (icons)
🧩 Browser Extension
Chrome Extension (Manifest V3)
Service worker (background script)
Content scripts for page analysis
Uses Chrome APIs:
runtime
tabs
storage
alarms
⚙️ Dev & Infrastructure
Docker & Docker Compose setup
Redis & Celery support (for future async tasks & scaling)
🚀 Detection System (Core Innovation)

Our extension uses 3-layer phishing detection:

1️⃣ Backend AI Detection (API)
Sends full URL to backend
ML model analyzes and returns:
Safe / Suspicious / Phishing
Used in extension popup and badge
2️⃣ Real-Time Browser Monitoring
Background script continuously scans active tabs
Displays warning badges:
❗ Phishing
⚠️ Suspicious
3️⃣ On-Page Link Analysis 🔥
Scans all links on a webpage
Detects:
Fake domains
Misleading anchor text
Phishing keywords
Highlights risky links visually for the user
⚙️ How It Works
User opens a website or email
Extension extracts:
URL
Email content & headers
Data is sent to backend API
ML model processes the input
Prediction is returned:
✅ Safe
⚠️ Suspicious
❌ Phishing
User receives a real-time warning via UI and browser badge
💡 Impact
Helps prevent financial fraud and data theft
Protects non-technical users from cyber threats
Raises awareness about phishing attacks
Provides real-time, proactive security