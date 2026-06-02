from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration, loaded from environment / .env."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/cve.db"

    nvd_api_key: str | None = None
    nvd_results_per_page: int = 2000
    request_timeout_seconds: int = 60

    poll_interval_minutes: int = 60
    initial_lookback_days: int = 7

    slack_webhook_url: str | None = None
    google_chat_webhook_url: str | None = None
    notify_min_cvss: float = 0.0
    public_base_url: str = "http://localhost:8000"

    default_watches: str = "linux kernel,php,symfony,postgresql,nginx"

    @property
    def default_watch_list(self) -> list[str]:
        return [w.strip() for w in self.default_watches.split(",") if w.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
