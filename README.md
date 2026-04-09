# PhishNet

AI-powered phishing URL and email detection platform with a FastAPI backend, React dashboard, and Chrome extension.

## Table Of Contents
- [Overview](#overview)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Core Features](#core-features)
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Run Locally](#run-locally)
- [Run With Docker](#run-with-docker)
- [Load The Browser Extension](#load-the-browser-extension)
- [API Endpoints](#api-endpoints)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Current Notes](#current-notes)

## Overview
PhishNet is a phishing detection system built around three connected parts:
- A FastAPI backend for phishing URL scanning, email analysis, authentication, dashboard analytics, and reporting.
- A React frontend dashboard for manual scanning and monitoring.
- A Chrome extension for real-time URL checks and Gmail email warnings.

The project is designed for the problem statement: phishing URL and email detection through intelligent, real-time analysis integrated into browsing and email workflows.

## Project Structure
```text
phishing-system/
+-- backend/               FastAPI backend, ML logic, models, tests
+-- frontend/              React + Vite dashboard
+-- extension/             Chrome extension (Manifest V3)
+-- docker-compose.yml     Multi-service local stack
+-- .env.example           Root environment example
+-- README.md
```

## Tech Stack
### Backend
- FastAPI
- SQLAlchemy Async
- Alembic
- PostgreSQL
- Redis
- scikit-learn
- Transformers / Torch

### Frontend
- React
- Vite
- Zustand
- Tailwind CSS
- Axios

### Extension
- Chrome Extension Manifest V3
- Background service worker
- Content scripts for web pages and Gmail

## Core Features
- URL phishing detection
- Email content and header analysis
- Browser extension quick checks
- Gmail email warning banner
- Dashboard analytics and reports
- Threat indicator management
- JWT-based authentication

## Prerequisites
Install these before running the project locally:
- Python 3.11+
- Node.js 18+
- npm
- PostgreSQL 13+ or 15+
- Redis 7+
- Google Chrome or any Chromium-based browser for the extension
- Docker Desktop, if you want to use Docker

## Environment Setup
### 1. Backend environment file
Create or update:
- [`backend/.env`](d:/SyntaXSurvivor/phishing-system/backend/.env)

You can copy from the root sample and adjust values as needed.

Example values:
```env
APP_ENV=development
APP_DEBUG=true
SECRET_KEY=change-me
JWT_SECRET_KEY=change-me-jwt-secret
DATABASE_URL=postgresql+asyncpg://phishnet:phishnet_pass@localhost:5432/phishnet
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
CORS_ALLOW_CREDENTIALS=true
```

### 2. Frontend environment file
Optional but recommended for local frontend development:
- `frontend/.env`

Add:
```env
VITE_API_URL=http://localhost:8000/api/v1
```

If this file is missing, the Vite proxy can still forward `/api` requests to the backend during local development.

## Run Locally
## 1. Clone and enter the project
```powershell
git clone <your-repo-url>
cd phishing-system
```

## 2. Start PostgreSQL and Redis
Make sure both services are running on these defaults:
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

## 3. Create the local PostgreSQL database
If PostgreSQL is installed locally, create the database and user:

```sql
CREATE USER phishnet WITH PASSWORD 'phishnet_pass';
CREATE DATABASE phishnet OWNER phishnet;
GRANT ALL PRIVILEGES ON DATABASE phishnet TO phishnet;
```

If the user already exists, you only need:
```sql
CREATE DATABASE phishnet OWNER phishnet;
```

## 4. Set up the backend
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Optional model setup:
```powershell
python -m spacy download en_core_web_sm
```

## 5. Run database migrations
From the `backend` directory:
```powershell
alembic upgrade head
```

## 6. Start the backend server
From the `backend` directory:
```powershell
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Backend URLs:
- API base: `http://localhost:8000/api/v1`
- Swagger docs: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

## 7. Set up the frontend
Open a second terminal:
```powershell
cd frontend
npm install
npm run dev
```

Frontend URL:
- `http://localhost:5173`

## 8. Optional backend utility commands
Train the email NLP model:
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
python scripts\train_email_nlp_model.py
```

Run tests:
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
```

Run a focused test file:
```powershell
pytest tests\test_api.py
```

## Run With Docker
### 1. Start the main app services
From the project root:
```powershell
docker compose up --build postgres redis backend frontend
```

Access points:
- Frontend: `http://localhost:3000`
- Backend: `http://localhost:8000`
- Docs: `http://localhost:8000/docs`

### 2. Stop containers
```powershell
docker compose down
```

### 3. Stop containers and remove volumes
```powershell
docker compose down -v
```

## Load The Browser Extension
### 1. Start backend first
The extension expects the backend at one of these URLs:
- `http://localhost:8000`
- `http://127.0.0.1:8000`

### 2. Open Chrome extensions page
Go to:
- `chrome://extensions/`

### 3. Enable developer mode
Turn on `Developer mode`.

### 4. Load the extension
Click `Load unpacked` and select:
- [`extension`](d:/SyntaXSurvivor/phishing-system/extension)

### 5. Test the extension
- Open a website and use the popup to scan the current URL.
- Open Gmail to let the content script inspect opened emails.

## API Endpoints
### Auth
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/api-key`
- `POST /api/v1/auth/change-password`

### URL Scanning
- `POST /api/v1/urls/scan`
- `POST /api/v1/urls/batch`
- `GET /api/v1/urls`
- `GET /api/v1/urls/{scan_id}`
- `POST /api/v1/extension/check`

### Email Scanning
- `POST /api/v1/emails/scan`
- `POST /api/v1/emails/scan-quick`

### Threat Intelligence
- `GET /api/v1/threats`
- `POST /api/v1/threats`
- `POST /api/v1/threats/lookup`

### Dashboard And Reports
- `GET /api/v1/dashboard/stats`
- `GET /api/v1/dashboard/trend`
- `GET /api/v1/dashboard/top-threats`
- `GET /api/v1/dashboard/recent`
- `POST /api/v1/reports/generate`

## Testing
### Backend tests
```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pytest
```

### With coverage
```powershell
pytest --cov=app --cov-report=term-missing
```

### Frontend lint
```powershell
cd frontend
npm install
npm run lint
```

### Frontend production build
```powershell
npm run build
```

## Troubleshooting
### Backend cannot connect to PostgreSQL
Check:
- PostgreSQL service is running.
- `DATABASE_URL` in `backend/.env` matches your local username, password, host, port, and database name.
- The `phishnet` database exists.

### Backend cannot connect to Redis
Check:
- Redis is running on `localhost:6379`.
- `REDIS_URL` in `backend/.env` is correct.

### Frontend cannot reach backend
Check:
- Backend is running on port `8000`.
- `frontend/.env` contains `VITE_API_URL=http://localhost:8000/api/v1`, or use the Vite proxy with `/api` routes.

### Extension shows API errors
Check:
- Backend is running.
- Extension host permissions still include `localhost:8000`.
- If needed, reload the unpacked extension after backend changes.

### Alembic migration issues
Run from the `backend` directory:
```powershell
alembic current
alembic history
alembic upgrade head
```

## Current Notes
- The main backend routes for auth, URLs, dashboard, threats, and reports are now wired to real services.
- The browser extension is designed around `http://localhost:8000` during local development.
- The Docker Compose file includes Celery-related services, but the current repository does not include an `app.tasks` module yet. Because of that, these commands are not ready in the current codebase:

```powershell
docker compose up celery-worker celery-beat flower
```

Use the main app services for now:
```powershell
docker compose up --build postgres redis backend frontend
```

