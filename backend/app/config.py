from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central config, loaded from env vars / .env. Never hardcode secrets here."""

    model_config = SettingsConfigDict(env_file=".env")

    redis_url: str = "redis://localhost:6379/0"
    api_key: str = "changeme"  # shared-secret auth; swap for JWT/OAuth before real deployment
    investigation_ttl_seconds: int = 60 * 60 * 24  # how long results live in Redis (24h)
    report_dir: str = "/tmp/osint_reports"
    max_concurrent_jobs: int = 5  # worker concurrency; tune down if source APIs rate-limit hard


settings = Settings()
