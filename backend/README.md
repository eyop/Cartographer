# OSINT backend

FastAPI service + arq worker. Two processes share one Redis instance:
the API enqueues jobs, the worker runs the collect -> normalize -> synthesize
pipeline and writes results back to Redis for the API to serve.

## Run locally

```bash
cp .env.example .env
pip install -r requirements.txt

# terminal 1
uvicorn app.main:app --reload

# terminal 2
arq app.workers.worker.WorkerSettings
```

Requires a local Redis (`docker run -p 6379:6379 redis:7-alpine`).

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | /investigations | Kick off an investigation, returns 202 + job id |
| GET | /investigations/{id} | Poll status (queued/running/completed/failed) |
| GET | /investigations/{id}/graph | Entity/relationship graph for the D3 view |
| GET | /investigations/{id}/report | PDF report (week 7) |
| GET | /health | Liveness check |

All `/investigations` routes require an `X-API-Key` header.

## Status

Weeks 2-4 (collectors, normalization, synthesis) are stubbed with clear
TODOs in `app/collectors/`, `app/synthesis/chain.py`, and
`app/workers/tasks.py`. The API and job queue are fully wired and testable
end to end against the stub — real collector logic drops in without
touching the API surface.
