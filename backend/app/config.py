from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central config, loaded from env vars / .env. Never hardcode secrets here."""

    model_config = SettingsConfigDict(env_file=".env")

    redis_url: str = "redis://localhost:6379/0"
    api_key: str = "changeme"
    investigation_ttl_seconds: int = 60 * 60 * 24
    report_dir: str = "/tmp/osint_reports"
    max_concurrent_jobs: int = 5

    # --- Source API keys ---
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    github_token: str = ""
    hibp_api_key: str = ""

    # --- LLM (synthesis chain, week 4) ---
    openai_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_temperature: float = 0.1
    llm_max_tokens: int = 4096


settings = Settings()
