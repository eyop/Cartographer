# Cartographer — Build Plan & Architecture Document

## 1. Project Overview

**Cartographer** is an AI-powered OSINT intelligence aggregator. A user submits
a single target identifier (a domain, email, company name, or person name) and
confirms they are authorized to investigate it. The system fans out to multiple
public data sources in parallel, caches responses, normalizes them into a
shared entity/relationship graph, runs a two-stage LLM synthesis chain, and
delivers a structured threat profile + D3 entity graph via a React dashboard.
A one-click PDF export produces a client-ready report with raw-finding
attribution.

### Design Principles

1. **One identifier type per request.** The tool takes one target at a time
   and routes to source-specific collectors. Keeps the async layer simple.
2. **Passive only.** Every collector hits public APIs or public records
   (crt.sh, GitHub Search, Shodan's indexed data, Cloudflare DoH, HIBP). No
   active scanning, credential testing, or login attempts anywhere.
3. **Rate limits in code, not just in READMEs.** Each source has a Redis-backed
   token bucket whose capacity and refill rate match the source's documented
   limits.
4. **Cache everything.** Raw responses cached keyed by
   `source:sha256(query)` with per-source TTLs.
5. **Normalize once, consume everywhere.** Single normalization layer
   converts `RawFinding[]` into `{entities, relationships}` graph.
6. **Structured synthesis, not prose.** LangChain chain emits a Pydantic
   `ThreatProfile` with citations back to source records.
7. **Data minimization + authorization.** Raw findings purged on schedule.
   Every investigation requires an explicit `authorized` checkbox.

## 2. Architecture

```
┌──────────┐   POST /investigations   ┌──────────┐
│  Browser │  ──────────────────────► │  FastAPI │  (port 8000)
│  (React) │                          │   API    │
└──────────┘                          └────┬─────┘
                                          │  enqueue arq job
                                          ▼
                                  ┌───────────────┐
                                  │  arq Worker   │
                                  │  (separate   │
                                  │   process)  │
                                  └──────┬──────┘
                                         │
           ┌────────────┬────────────┬───┼───┬────────────┬────────────┐
           │ Shodan     │ GitHub     │crt │DNS│VirusTotal │  HIBP      │
           │            │            │.sh │   │            │            │
           └──────┬─────┴──────┬─────┴───┴───┴──────┬─────┴──────┬─────┘
                  │            │                    │            │
                  └──── Rate Limiter (Redis) ───────┘
                  └──── Response Cache (Redis) ─────┘
                           per-source TTL
                                          │
                    RawFinding[] ─────────►│
                           │
                           ▼
              ┌─────────────────────────┐
              │  normalize.py           │  RawFinding[] → {entities, relationships}
              └───────────┬──────────────┘
                          │
                          ▼
     ┌─────────────────────────────────┐
     │  LangChain Two-Stage Chain     │
     │  Stage 1: Extraction            │  tag findings → entity types + relevance
     │  Stage 2: Synthesis             │  compose ThreatProfile w/ citations
     └─────────────────┬───────────────┘
                       │
                       ▼
     ┌─────────────────────────────────┐
     │  Redis (investigation:{id})    │  store InvestigationRecord + result
     └─────────────────────────────────┘
                       │
     GET /investigations/{id}  ◄──────┐
     GET /investigations/{id}/graph ──► D3 graph
     GET /investigations/{id}/report ──► PDF (week 7)
```

**Data flow:** User POSTs target → API enqueues arq job → worker fans out to
collectors (rate-limited + cached) → normalize → synthesize → store in Redis
→ frontend polls status and renders D3 graph.

## 3. Target → Source Routing Matrix

| target_type | collectors |
|-------------|------------|
| domain | dns, crtsh, shodan, virustotal |
| email | hibp, virustotal |
| company | github, crtsh, shodan, virustotal |
| person | github, hibp |

## 4. Data Models

All models: `app/models/entity.py` + `app/models/investigation.py`.
Single source of truth for shape.

### RawFinding (per-source output)
```python
RawFinding:
  source: str           # "shodan", "github", "crtsh", "dns", "virustotal", "hibp"
  query: str            # the original target string
  timestamp: datetime
  payload: dict[str, Any]    # raw API response body
  entity_refs: list[str]     # entity IDs extracted (set during normalization)
```

### Entity / Relationship (normalized graph)
```python
Entity:
  id: str
  type: "domain" | "ip" | "email" | "person" | "org" | "repo" | "cve"
  value: str
  confidence: float
  first_seen: datetime
  sources: list[str]

Relationship:
  source_entity_id: str
  target_entity_id: str
  type: "resolves_to" | "employee_of" | "leaked_in" | "hosts" | "owns" | "mentions"
  confidence: float
```

### ThreatProfile (synthesis output)
```python
ThreatProfile:
  target: str
  summary: str
  risk_indicators: list[str]   # each citing source + finding
  entities: list[Entity]
  relationships: list[Relationship]
  generated_at: datetime
  model_version: str
```

### Investigation (job state)
```python
InvestigationCreate:  {target, target_type, authorized}
InvestigationRecord:  {id, target, target_type, status, created_at, updated_at, progress, error}
InvestigationResult:  {investigation_id, threat_profile, graph}
```

## 5. Phase-by-Phase Implementation Plan

### Phase 1 — Infrastructure: Rate Limiter + Cache

**rate_limiter.py** — `TokenBucket` (Redis-backed, Lua atomic acquire),
`RateLimiter` registry with per-source capacity/refill constants.

**cache.py** — `ResponseCache` with per-source TTLs. Key format:
`cache:{source}:{sha256(query)[:16]}`.

### Phase 2 — Async Collectors (Week 2)

Each extends `BaseCollector`, returns `list[RawFinding]`. Pattern:
check cache → acquire rate token → httpx call → cache response → return finding.

| Module | API | Key? | Endpoint |
|--------|-----|------|----------|
| dns.py | Cloudflare DoH | No | GET dns.cloudflare.com/dns-query |
| crtsh.py | crt.sh | No | GET crt.sh/?q={t}&output=json |
| github.py | GitHub Search | Yes | GET api.github.com/search/code |
| shodan.py | Shodan API | Yes | GET api.shodan.io/shodan/host |
| virustotal.py | VT v3 | Yes | GET api/v3/domains |
| hibp.py | HIBP v3 | Yes | GET api/v3/breachedaccount |

**manager.py** — `CollectorManager`: instantiates collectors,
`get_collectors(target_type)` returns the right set per routing matrix.

### Phase 3 — Normalization (Week 3)

**normalize.py** — `normalize(raw_findings) -> dict` returning
`{"entities", "relationships"}`. Per-source normalizers parse payloads.
Entity dedup by `(type, value)`, relationship dedup by `(source_id, target_id, type)`.

### Phase 4 — LangChain Synthesis (Week 4)

**chain.py** — `synthesize_threat_profile(graph, raw_findings, target) -> ThreatProfile`.
Two-stage chain: (1) extraction (tag findings → entity types + relevance),
(2) synthesis (compose ThreatProfile with citations). Structured output via
Pydantic parser / tool-calling. Fallback: stub summary from graph if no key.

### Phase 5 — Worker Pipeline (Week 2-4)

**tasks.py** (rewrite stub): get collectors → asyncio.gather → normalize →
synthesize → store in Redis → update InvestigationRecord.

### Phase 6 — API (Week 5)

Wire `GET /{id}/report` to `report.render_report_pdf()`.

### Phase 7 — PDF Report (Week 7)

**report.py** — `render_report_pdf(profile) -> bytes` using reportlab.
Page 1: exec summary. Page 2+: risk indicators. Appendices: entities table,
relationships table, raw findings per source with attribution.

### Phase 8 — React Dashboard (Week 6)

**frontend/** — Vite + React + d3. Components: `InvestigationForm`,
`InvestigationStatus` (polling), `EntityGraph` (D3 force-directed, nodes colored
by type, edges labeled by relationship), `ThreatReport` (summary + risk
indicators + PDF download).

### Phase 9 — Guardrails & Hardening (Week 8)

- `docs/acceptable-use-policy.md` — passive-only, auth gate, data minimization.
- Extend `tests/` — conftest, collector tests, normalize tests, synthesis tests.
- `.gitignore` — Python/Node/Docker/reports.
- README updates — ethical use front and center.

## 6. Dependency Additions

| Package | Purpose | Week |
|---------|---------|------|
| `dnspython>=2.7` | DNS resolution (fallback) | 2 |
| `reportlab>=4.2` | PDF report generation | 7 |
| `langchain>=0.3` | LLM chain orchestration | 4 |
| `langchain-openai>=0.2` | OpenAI LLM integration | 4 |
| `openai>=1.50` | Structured output / tool-calling | 4 |

Frontend: `react`, `react-dom`, `d3`, `vite`, `@vitejs/plugin-react`.

## 7. Execution Order

1. `.gitignore`, `requirements.txt`, `config.py`, `.env.example` — infra ✅
2. `rate_limiter.py`, `cache.py` — rate limiting + caching ✅
3. `base_http.py`, `dns.py`, `crtsh.py` — no-key collectors
4. `github.py`, `shodan.py` — keyed collectors
5. `virustotal.py`, `hibp.py` — more keyed collectors
6. `manager.py`, `normalize.py` — collector routing + normalization
7. `tasks.py` — wire pipeline together
8. `chain.py`, `extraction.py`, `synthesis.py` — LangChain synthesis
9. `report.py` — PDF export
10. Frontend scaffold — React + Vite + D3
11. Tests — unit + integration
12. Docs — acceptable-use policy, README updates