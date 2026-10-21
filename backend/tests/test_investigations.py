from fastapi.testclient import TestClient

from app.dependencies import get_redis, verify_api_key
from app.main import app

client = TestClient(app)


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def set(self, key, value, ex=None):
        self.store[key] = value

    async def get(self, key):
        return self.store.get(key)


def test_create_investigation_requires_authorization():
    app.dependency_overrides[get_redis] = lambda: None
    app.dependency_overrides[verify_api_key] = lambda: None

    try:
        resp = client.post(
            "/investigations",
            json={"target": "example.com", "target_type": "domain", "authorized": False},
        )
        assert resp.status_code == 400
        assert "authorization" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


def test_create_investigation_returns_503_when_queue_unavailable(monkeypatch):
    fake_redis = FakeRedis()

    async def fake_redis_dep():
        return fake_redis

    async def fake_get_arq_pool():
        raise RuntimeError("Redis unavailable")

    app.dependency_overrides[get_redis] = fake_redis_dep
    app.dependency_overrides[verify_api_key] = lambda: None
    monkeypatch.setattr("app.routers.investigations.get_arq_pool", fake_get_arq_pool)

    try:
        resp = client.post(
            "/investigations",
            json={"target": "example.com", "target_type": "domain", "authorized": True},
        )
        assert resp.status_code == 503
        assert "queue" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


def test_create_investigation_rejects_blank_target():
    app.dependency_overrides[get_redis] = lambda: None
    app.dependency_overrides[verify_api_key] = lambda: None

    try:
        resp = client.post(
            "/investigations",
            json={"target": "   ", "target_type": "domain", "authorized": True},
        )
        assert resp.status_code == 400
        assert "empty" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


def test_create_investigation_rejects_mismatched_target_type():
    app.dependency_overrides[get_redis] = lambda: None
    app.dependency_overrides[verify_api_key] = lambda: None

    try:
        resp = client.post(
            "/investigations",
            json={"target": "user@example.com", "target_type": "domain", "authorized": True},
        )
        assert resp.status_code == 400
        assert "domain" in resp.json()["detail"].lower()
    finally:
        app.dependency_overrides.clear()


def test_create_investigation_uses_in_memory_queue_fallback(monkeypatch):
    async def fake_redis_dep():
        return FakeRedis()

    app.dependency_overrides[get_redis] = fake_redis_dep
    app.dependency_overrides[verify_api_key] = lambda: None

    async def fake_pool_init():
        raise RuntimeError("Redis unavailable")

    monkeypatch.setattr("app.services.job_queue.create_pool", fake_pool_init)

    try:
        resp = client.post(
            "/investigations",
            json={"target": "example.com", "target_type": "domain", "authorized": True},
        )
        assert resp.status_code == 202
        assert resp.json()["target"] == "example.com"
    finally:
        app.dependency_overrides.clear()


def test_create_investigation_executes_local_fallback_job(monkeypatch):
    async def fake_redis_dep():
        return FakeRedis()

    app.dependency_overrides[get_redis] = fake_redis_dep
    app.dependency_overrides[verify_api_key] = lambda: None

    async def fake_pool_init():
        raise RuntimeError("Redis unavailable")

    monkeypatch.setattr("app.services.job_queue.create_pool", fake_pool_init)

    try:
        resp = client.post(
            "/investigations",
            json={"target": "example.com", "target_type": "domain", "authorized": True},
        )
        assert resp.status_code == 202
        job_id = resp.json()["id"]

        for _ in range(50):
            result = client.get(f"/investigations/{job_id}/graph")
            if result.status_code == 200:
                assert result.json() == {"entities": [], "relationships": []}
                break
            import time
            time.sleep(0.05)
        else:
            raise AssertionError("fallback job did not produce graph output")
    finally:
        app.dependency_overrides.clear()


def test_run_investigation_handles_no_available_collectors(monkeypatch):
    import asyncio
    import json

    from app.workers.tasks import run_investigation

    class FakeRedis:
        def __init__(self):
            self.store = {}

        async def set(self, key, value, ex=None):
            self.store[key] = value

        async def get(self, key):
            return self.store.get(key)

    fake_redis = FakeRedis()

    class FakeManager:
        def __init__(self, *args, **kwargs):
            pass

        def get_collectors(self, *args, **kwargs):
            return []

    async def fake_synthesize(target, graph, findings):
        class P:
            def __init__(self):
                self.target = target
                self.summary = "empty run"
                self.risk_indicators = []
                self.entities = []
                self.relationships = []
                self.generated_at = None
                self.model_version = "fallback-v1"

            def model_dump(self):
                return {
                    "target": self.target,
                    "summary": self.summary,
                    "risk_indicators": self.risk_indicators,
                    "entities": self.entities,
                    "relationships": self.relationships,
                    "generated_at": None,
                    "model_version": self.model_version,
                }

        return P()

    monkeypatch.setattr("app.workers.tasks.CollectorManager", FakeManager)
    monkeypatch.setattr("app.workers.tasks.normalize", lambda items: {"entities": [], "relationships": []})
    monkeypatch.setattr("app.workers.tasks.synthesize_threat_profile", fake_synthesize)

    async def _go():
        await run_investigation({"redis": fake_redis}, "job-123", "example.com", "domain")
        result = json.loads(fake_redis.store["investigation:job-123:result"])
        assert result["graph"] == {"entities": [], "relationships": []}
        assert result["threat_profile"]["target"] == "example.com"

    asyncio.run(_go())
