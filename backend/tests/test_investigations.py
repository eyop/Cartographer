from app.dependencies import get_redis, verify_api_key
from app.main import app

client = __import__("fastapi").testclient.TestClient(app)


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
