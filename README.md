# Email Threat Forensics Platform

Hackathon MVP for uploading `.eml` messages and producing an explainable forensic assessment.

## Stack

- React + Vite
- Django + Django REST Framework
- SQLite
- PyTorch + scikit-learn compatible ML service

## Run locally

### Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python manage.py migrate
.venv\Scripts\python manage.py runserver
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The API runs at `http://localhost:8000`.

The RoBERTa detector loads only from `C:\Users\Jahnavi\Downloads\New folder`.
To use another local copy without changing code, set `HF_EMAIL_FRAUD_MODEL_PATH`
to the directory containing `config.json`, `model.safetensors`, and tokenizer files.

## Current MVP

- Safe `.eml` ingestion and SHA-256 audit hash
- Metadata, body, relay-hop, URL, domain, IP, and email extraction
- Authentication-Results interpretation and sender-domain mismatch checks
- Explainable deterministic threat scoring
- PyTorch/sklearn-ready phishing classifier with a deterministic fallback
- SQLite persistence and report endpoint
- Responsive forensic dashboard
