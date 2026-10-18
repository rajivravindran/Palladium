# Sentinel

Runtime scope enforcement for AI agents and business services.
**Every workload has a scope. Sentinel catches actions outside it, whoever is behind them.**

## Layout
| Folder | What | Status |
|---|---|---|
| `lab/images/` | Builds a small lab container image from host binaries | ✅ works |
| `sentineld/` | eBPF sensor (file open / exec / connect, enrolled containers only) + event format + profile loader | ✅ compiles, not yet wired |
| `api/` | FastAPI hub: workloads, events, incidents, operator actions, audit log, live stream, Qwen3 summaries | ✅ 7 tests pass |
| policy layer | Decides allowed / prohibited / unresolved | ⏳ Rajiv |
| containment layer | Acts on decisions, reports results back to the API | ⏳ Rajiv |
| console UI | Operator screens | ⏳ next |

## Run the API
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install fastapi==0.115.6 "uvicorn[standard]==0.32.1" sqlalchemy==2.0.36 httpx==0.28.1 pytest==8.3.4 pydantic==2.10.4 "psycopg[binary]==3.2.3"
cd api
pytest -q tests                      # 7 tests
uvicorn sentinel_api.main:app --reload
```
Open http://127.0.0.1:8000/docs for the interactive API.

## Settings (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_DATABASE_URL` | `sqlite:///./sentinel.db` | Use `postgresql+psycopg://...` for Postgres |
| `SENTINEL_INGEST_TOKEN` | `dev-ingest-token` | Token for sensor / policy / containment layers |
| `SENTINEL_OPERATORS` | `rajiv:dev-operator-token` | `name:token,name2:token2` |
| `SENTINEL_ACTION_WEBHOOK` | – | URL where operator actions are POSTed for the containment layer |
| `SENTINEL_LLM_BASE_URL` | `http://localhost:11434/v1` | OpenAI-compatible endpoint (Ollama / MLX) |
| `SENTINEL_LLM_MODEL` | `qwen3:8b` | Summary model |

⚠️ Change both tokens before any pilot.

## How the layers talk to the API
- **Policy layer** → `POST /api/v1/workloads`, `POST /api/v1/incidents` (ingest token)
- **Containment layer** → `PATCH /api/v1/incidents/{id}/response` once it acts;
  picks up operator requests from `GET /api/v1/actions` (or the webhook) and reports back with
  `POST /api/v1/actions/{id}/result`
- **Console** → operator endpoints (`/api/v1/incidents`, `/actions`, `/summary`, `/audit`, `/stream`)

The API never freezes, resumes or terminates anything itself.

## Qwen3-8B summaries
On the Mac: `ollama pull qwen3:8b && ollama serve`.
The model sees **Channel A facts only**. Any event ID it invents is stripped, and the summary is marked not grounded.
If the model is offline, a deterministic summary is used instead.
