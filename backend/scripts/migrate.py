"""Apply every SQL migration in backend/migrations, in filename order.

Each file is additive and safe to run again, so this can be re-run after a pull.
Run from the repository root: backend/.venv/Scripts/python backend/scripts/migrate.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.config import settings

MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


def main():
    import pymssql
    if not settings.db_enabled or not settings.db_host:
        raise SystemExit("SQL Server is not configured.")
    files = sorted(MIGRATIONS.glob("*.sql"))
    if not files:
        raise SystemExit(f"No migrations found in {MIGRATIONS}")
    with pymssql.connect(server=settings.db_host, port=str(settings.db_port),
            user=settings.db_user, password=settings.db_password, database=settings.db_name,
            timeout=settings.db_timeout_seconds, login_timeout=settings.db_timeout_seconds) as conn:
        for path in files:
            with conn.cursor() as cur:
                cur.execute(path.read_text(encoding="utf-8"))
            conn.commit()
            print(f"Applied {path.name}")
    print(f"{len(files)} migration(s) applied.")


if __name__ == "__main__":
    main()
