# Repository Guidelines

## Project Structure & Module Organization

AgentGuard has a FastAPI backend and a React/Vite frontend.

- `backend/app/main.py` defines API routes, including intent compilation, evaluation, attacks, audit, and metrics.
- `backend/app/engine.py` contains the current transaction evaluation logic, policy checks, risk scoring, and idempotency key generation.
- `backend/app/store.py` manages SQLite state in `backend/agentguard.db`.
- `backend/app/models.py` defines Pydantic request and response models.
- `frontend/src/main.tsx` implements the React UI, including the Attack Lab.
- `frontend/src/style.css` contains global styling.

No `tests/` or asset directories exist yet.

## Build, Test, and Development Commands

Backend setup and run:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend setup and run:

```bash
cd frontend
npm install
npm run dev
```

Frontend build check:

```bash
cd frontend
npm run build
```

This runs TypeScript compilation followed by a Vite production build. No backend build command is configured.

## Coding Style & Naming Conventions

Keep changes small and consistent with the existing code. Backend modules use simple function names such as `compile_intent`, `evaluate`, and `get_agent`. Use snake_case in Python and camelCase for React handlers or local TypeScript values.

Use Pydantic models for API shapes and keep business rules in `engine.py` rather than embedding them in route handlers. Keep frontend UI behavior in `main.tsx` unless it grows enough to justify components.

## Testing Guidelines

No testing framework is configured yet. For backend additions, prefer focused pytest coverage near the backend code, especially for policy, risk, idempotency, and attack scenarios. For frontend additions, add a test runner before introducing UI tests and document the command in `package.json`.

Until tests exist, verify manually with the backend on `localhost:8000` and the frontend on `localhost:5173`.

## Commit & Pull Request Guidelines

The current Git history uses a conventional commit style, for example `feat: initialize frontend with React, Vite, and TypeScript setup`. Continue with short, imperative messages like `fix: block expired authorizations`.

Pull requests should include a concise summary, testing or manual verification notes, and screenshots for visible frontend changes. Link related issues when available and call out any changes to the SQLite schema or evaluation behavior.

## Security & State Notes

Treat AI-generated intent as untrusted input. Preserve the existing flow: intent compilation, capability and policy checks, risk decision, idempotency, mock payment, and tamper-evident audit. Do not commit virtual environments, dependency folders, local databases, or generated cache files.
