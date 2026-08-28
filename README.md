# Cartographer

AI-powered OSINT intelligence aggregator.

```
osint-aggregator/
├── backend/            FastAPI API + arq worker (this week's focus)
│   ├── app/
│   │   ├── main.py             FastAPI app + routers
│   │   ├── config.py           env-driven settings
│   │   ├── dependencies.py     Redis + API-key auth
│   │   ├── models/              shared Pydantic schema (Entity, ThreatProfile, Investigation...)
│   │   ├── routers/             investigations.py, health.py
│   │   ├── services/            job_queue.py (arq), report.py (PDF, week 7)
│   │   ├── workers/             tasks.py (the pipeline), worker.py (arq settings)
│   │   ├── collectors/          BaseCollector + per-source modules (week 2)
│   │   └── synthesis/           LangChain chain (week 4)
│   ├── tests/
│   ├── requirements.txt
│   ├── Dockerfile
│   └── .env.example
├── frontend/            React + D3 dashboard (week 6)
├── reports/              generated PDF output (gitignored)
└── docker-compose.yml    redis + api + worker
```

## Status
- [x] Repo scaffold, Docker Compose, API + job queue (this week)
- [ ] Async collectors (week 2)
- [ ] Redis cache + normalization (week 3)
- [ ] LangChain synthesis (week 4)
- [ ] React dashboard + D3 graph (week 6)
- [ ] PDF report export (week 7)
