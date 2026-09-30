"""Apply the additive scan-evidence migration using the configured SQL database.

Run from the repository root: backend/.venv/Scripts/python backend/scripts/migrate_scan_evidence.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import settings


def main():
    import pymssql
    if not settings.db_enabled or not settings.db_host:
        raise SystemExit("SQL Server is not configured.")
    sql = (Path(__file__).resolve().parents[1] / "migrations/001_scan_evidence.sql").read_text()
    with pymssql.connect(server=settings.db_host, port=str(settings.db_port),
            user=settings.db_user, password=settings.db_password, database=settings.db_name,
            timeout=settings.db_timeout_seconds, login_timeout=settings.db_timeout_seconds) as conn:
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
    print("Scan evidence migration applied.")


if __name__ == "__main__":
    main()
