# ScamRead

ScamRead is a minimal FastAPI web app that analyzes pasted messages or links for scam risk using local rule-based logic.

## Features

- `POST /analyze` endpoint
- Structured JSON output
- Simple static frontend
- Graceful API error handling

## Local Setup

1. Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
uvicorn app.main:app --reload
```

4. Open the app:

```text
http://127.0.0.1:8000
```

## Deploy on Render

This repo includes `render.yaml`, so Render can create the web service from the blueprint.

1. Push this project to GitHub, GitLab, or Bitbucket.
2. In Render, create a new Blueprint from the repo.
3. Deploy.

Render will use:

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Health checks are served from:

```text
/health
```

## API

### POST `/analyze`

Request:

```json
{
  "text": "Your suspicious message or link"
}
```

Response:

```json
{
  "risk_score": 85,
  "risk_level": "high",
  "scam_type": "phishing",
  "red_flags": ["Urgent language", "Suspicious login link"],
  "explanation": "The message pressures the user to click a link and verify account details.",
  "recommended_action": "Do not click the link. Visit the service directly and report the message."
}
```
