from pathlib import Path

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
    urlhaus_timeout_seconds: float = 8.0
    cache_ttl_seconds: int = 900
    heuristic_benign_threshold: int = 80
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Page-analysis stage: fetches the destination in a locked-down headless
    # browser and classifies its markup with the Laya phishing model.
    page_model_dir: str = str(ROOT_DIR / "ai/markuplm/artifacts/laya_v2")
    page_stage_enabled: bool = True
    page_fetch_concurrency: int = 2
    page_fetch_timeout_seconds: float = 20.0
    page_fetch_budget_seconds: float = 45.0
    page_fetch_proxy: str = ""


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
