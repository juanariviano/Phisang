from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BACKEND_DIR / "data"
WEB_SRC = ROOT_DIR / "web"
WEB_DIR = WEB_SRC / "dist" if (WEB_SRC / "dist").exists() else WEB_SRC


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    urlhaus_auth_key: str = ""
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    explanation_base_url: str = "https://generativelanguage.googleapis.com/v1beta/openai"
    explanation_api_key: str = ""
    explanation_model: str = "gemini-3.5-flash-lite"
    explanation_timeout_seconds: float = 35.0
    explanation_include_screenshot: bool = True
    rdap_enabled: bool = True
    rdap_timeout_seconds: float = 8.0
    urlhaus_timeout_seconds: float = 15.0
    cache_ttl_seconds: int = 900
    heuristic_benign_threshold: int = 80
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Page-analysis stage: fetches the destination in a locked-down headless
    # browser and classifies its markup with the Laya phishing model.
    page_model_dir: str = str(ROOT_DIR / "ai/markuplm/artifacts/laya_v3")
    page_stage_enabled: bool = True
    page_fetch_concurrency: int = 2
    page_fetch_timeout_seconds: float = 20.0
    page_fetch_budget_seconds: float = 45.0
    page_fetch_proxy: str = ""
    page_preview_enabled: bool = True

    # Scan history in SQL Server. The pipeline consults this before URLhaus, so a
    # repeat URL costs no rate-limit token and no browser fetch. Credentials come
    # from .env, which is gitignored; nothing here carries a default secret.
    db_enabled: bool = True
    db_host: str = ""
    db_port: int = 1433
    db_name: str = "PhisangDB"
    db_user: str = ""
    db_password: str = ""
    # Admin review of false-positive reports. Empty values disable the dashboard
    # entirely; nothing here has a default, so a misconfigured server is closed
    # rather than open. Generate them with scripts/admin_setup.py.
    admin_email: str = ""
    admin_password_hash: str = ""
    admin_totp_secret: str = ""
    admin_session_secret: str = ""
    admin_session_minutes: int = 60

    db_timeout_seconds: int = 10
    # A URLhaus listing stays true far longer than a "not listed" answer does.
    db_urlhaus_match_ttl_seconds: int = 86_400

    @field_validator("page_model_dir")
    @classmethod
    def _resolve_model_dir(cls, value: str) -> str:
        """Let PAGE_MODEL_DIR be written relative to the repository root.

        The API is started from backend/ as often as from the root, and a bare
        relative path would otherwise resolve against whichever one was used.
        """
        path = Path(value).expanduser()
        return str(path if path.is_absolute() else (ROOT_DIR / path).resolve())


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
