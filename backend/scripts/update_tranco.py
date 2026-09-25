"""Download the Tranco popularity ranking and keep its top domains.

Run from backend/:  python scripts/update_tranco.py [--top 100000]
Writes data/tranco_top.txt, which the analyzer reads at startup (restart the API
after refreshing). Tranco ranks registrable domains by aggregated traffic and is
far harder for a fresh phishing domain to enter than a hand-kept list.
"""

import argparse
import csv
import io
import sys
import zipfile
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.reputation import POPULAR_DOMAINS_PATH  # noqa: E402

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--top", type=int, default=100_000)
    args = parser.parse_args()

    response = httpx.get(TRANCO_URL, follow_redirects=True, timeout=120)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        rows = archive.read(archive.namelist()[0]).decode("utf-8")

    domains = []
    for rank, domain in csv.reader(io.StringIO(rows)):
        if int(rank) > args.top:
            break
        domains.append(domain.strip().lower())
    if len(domains) < min(args.top, 1000):
        sys.exit(f"refusing to write a suspiciously short list ({len(domains)} domains)")

    POPULAR_DOMAINS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = POPULAR_DOMAINS_PATH.with_suffix(".tmp")
    tmp.write_text("\n".join(domains) + "\n", encoding="utf-8")
    tmp.replace(POPULAR_DOMAINS_PATH)
    print(f"wrote {len(domains)} domains to {POPULAR_DOMAINS_PATH}")


if __name__ == "__main__":
    main()
