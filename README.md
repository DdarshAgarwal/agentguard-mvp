# AgentGuard

AgentGuard is a zero-trust control plane for autonomous financial agents.
It treats AI-generated payment intent as untrusted and evaluates it against server-side spending policy, signed capabilities, authorization boundaries, risk signals, replay protection, velocity controls and an atomic payment reservation.

## Demo flow

`User policy → AI intent → signed capability → AgentGuard decision → simulated payment → tamper-evident audit`

## Security controls

- HMAC-SHA256 signed, short-lived spending capabilities
- User-configurable daily and per-transaction limits
- Policy-version invalidation when limits change
- Server-side merchant, category and action authorization
- Prompt-injection detection
- Replay/idempotency protection
- Velocity controls
- Atomic SQLite budget + payment reservation with `BEGIN IMMEDIATE`
- Tamper-evident audit hash chain and integrity verification
- Input size and schema validation
- Security response headers and restricted CORS
- Production secret configuration through environment variables
- No frontend signing secrets
- Vite production builds without source maps
- Robots, sitemap, canonical metadata, structured data, favicon and social metadata

## Run locally

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Test

```bash
cd backend
.venv/bin/python -m pytest tests
```

The application uses simulated payments only; it does not move real money.
