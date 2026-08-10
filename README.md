# PII Anonymizer

Internal microservice of the **Business Robots AI** platform. It strips personal
data out of user messages *before* they reach a third-party LLM (OpenAI,
Anthropic, OpenRouter), and puts the real values back into the model's reply.

The LLM provider only ever sees `{{name_1}}` and `{{phone_1}}`. The mapping back
to `Алишер` and `+998901234567` never leaves our infrastructure.

This is a published excerpt of the Business Robots AI codebase, shared as a work
sample. See [COPYRIGHT.md](COPYRIGHT.md) for terms.

## Why it exists

Uzbekistan's personal-data law requires that the personal data of citizens be
processed on infrastructure located in Uzbekistan. A chatbot platform that pipes
raw customer messages to an API in another jurisdiction does not satisfy that.

Anonymizing on the way out and restoring on the way back lets the platform keep
using frontier models while the personal data itself stays home.

## How it works

```
user message
     │
     ▼
┌─────────────────┐   "Меня зовут Алишер, мой номер +998901234567"
│  /api/v1/       │
│  process        │──▶ regex pass ──▶ optional local LLM pass (Qwen2.5-3B GGUF)
└─────────────────┘
     │
     │ "Меня зовут {{name_1}}, мой номер {{phone_1}}"
     ▼
  third-party LLM  ◀── never sees the real values
     │
     │ "Приятно познакомиться, {{name_1}}! Наберём вас на {{phone_1}}."
     ▼
┌─────────────────┐
│  /api/v1/       │──▶ look up session mapping ──▶ substitute originals back
│  restore        │
└─────────────────┘
     │
     ▼
"Приятно познакомиться, Алишер! Наберём вас на +998901234567."
```

The placeholder↔original mapping is written to a **dedicated Postgres instance**,
isolated from the main application database, and encrypted at rest with
AES-256-CBC (`app/crypto.py`). Mappings are keyed by a short-lived session id.

### Detection

Two stages, the second one optional:

1. **Regex** (`app/anonymizer.py`) — deterministic, ~1 ms, covers the structured
   identifiers: PINFL (14 digits), passport, phone, bank card, INN, bank account
   (20 digits), email, dates, addresses.
2. **Local LLM** (`app/llm_service.py`) — Qwen2.5-3B-Instruct in GGUF via
   llama.cpp, `temperature=0`. Catches names and free-form addresses that regex
   cannot. Off by default (`PII_USE_LLM=False`) because regex plus a name
   dictionary covers production traffic at a fraction of the latency.

Names are the hard case: they are not structured, and Uzbek/Russian names
collide with ordinary vocabulary. `app/names_db.py` carries a curated dictionary
plus a per-tenant custom word list (stop-words and extra names) so each client
can tune precision without a redeploy.

Every detection carries a confidence score, stored alongside the mapping so
false positives can be audited after the fact.

## API

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /anonymize` | none | Raw anonymization, `[TYPE_001]` placeholders |
| `POST /deanonymize` | none | Inverse of the above |
| `POST /api/v1/process` | none | Platform integration, `{{type_1}}` placeholders |
| `POST /api/v1/restore` | none | Restore by `session_id` |
| `POST /api/v2/anonymize` | JWT / API token | Multi-tenant, per-user storage |
| `POST /api/v2/deanonymize` | JWT / API token | Multi-tenant restore |
| `POST /api/v2/openai-proxy` | JWT / API token | Drop-in OpenAI chat-completions proxy that anonymizes and restores around the call |
| `GET /api/v2/sessions`, `/mappings`, `/audit` | JWT / API token | Data viewer |
| `GET /health`, `/metrics` | none | Health + Prometheus |

The `v1` endpoints are unauthenticated by design: the service publishes no ports
and is reachable only on the internal Docker network by the platform backend.
The `v2` surface is authenticated because it exposes stored mappings.

`app/openai_proxy.py` is the interesting one — it accepts an OpenAI
chat-completions payload, anonymizes every message, forwards upstream, then
de-anonymizes the response. Callers integrate by changing a base URL.

## Running it

```bash
cp .env.example .env      # then fill in the secrets — none of them have defaults
docker build -t pii-anonymizer .
docker run --env-file .env -p 8100:8100 pii-anonymizer
```

Without Docker:

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8100
```

Interactive API docs at `http://localhost:8100/docs`. A web UI for testing,
browsing detections, and managing the custom dictionary is served at `/`.

Postgres is required for persistent mappings. Without it the service degrades to
an in-memory TTL cache — anonymization still works, but restores fail across
restarts.

## Configuration

All variables are prefixed `PII_`. See [.env.example](.env.example) for the full
list. The ones that matter:

| Variable | Meaning |
|---|---|
| `PII_ENCRYPTION_KEY` | AES key for mappings at rest. **Required.** |
| `PII_JWT_SECRET` | Signing key for `v2` access tokens. **Required.** |
| `PII_DB_*` | Postgres connection for the mapping store |
| `PII_API_KEY` | Shared key for the legacy `X-API-Key` path. Leave empty to keep it disabled. |
| `PII_USE_LLM` | `True` enables the local-LLM stage (slower, more accurate) |
| `PII_MODEL_PATH` | Path to the GGUF model when the LLM stage is on |

**No secret has a fallback value.** An unset `PII_API_KEY` disables the auth path
it belongs to rather than quietly accepting a key that is readable in this
source. An unset `PII_JWT_SECRET` generates an ephemeral one and logs an error,
so tokens stop surviving restarts and the misconfiguration surfaces immediately.

## Layout

```
app/
├── anonymizer.py      # regex engine, placeholder allocation, TTL cache
├── names_db.py        # name dictionary + per-tenant custom words
├── llm_service.py     # local Qwen2.5-3B GGUF stage
├── prompts.py         # extraction prompt for the LLM stage
├── openai_proxy.py    # anonymizing OpenAI chat-completions proxy
├── integration.py     # platform-facing {{placeholder}} API
├── crypto.py          # AES-256-CBC for mappings at rest
├── database.py        # platform Postgres, pooled
├── client_db.py       # per-tenant "bring your own database" support
├── auth_jwt.py        # JWT + API tokens, bcrypt
├── dependencies.py    # FastAPI auth dependencies
└── routers/           # auth, user, admin, data-viewer
```

Tenants who do not want their mappings in the platform database can point the
service at their own Postgres (`app/client_db.py`); the schema is downloadable
from the dashboard.
