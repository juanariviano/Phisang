"""Extract raw HTML pages from a phreshphish-style JSONL dataset into
standalone .html files, mirroring the layout of ai/markuplm/examples/
(one subfolder per label, one file per page).

Usage:
    python scripts/extract_dataset_html.py \
        --jsonl datasets/phreshphish_sample/train3000_val400_test400/train.jsonl \
                datasets/phreshphish_sample/train3000_val400_test400/val.jsonl \
                datasets/phreshphish_sample/train3000_val400_test400/test.jsonl \
        --out extracted \
        --per-label 20
"""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

LABEL_DIR = {"phish": "phishing", "benign": "benign"}


def slugify(netloc: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", netloc).strip("_").lower()
    return slug or "page"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jsonl", nargs="+", required=True, help="One or more input .jsonl files")
    parser.add_argument("--out", default="examples_extracted", help="Output directory")
    parser.add_argument("--per-label", type=int, default=None, help="Max pages to write per label (default: all)")
    parser.add_argument("--seed", type=int, default=42, help="Shuffle seed used when --per-label limits the pool")
    args = parser.parse_args()

    out_root = Path(args.out)
    counts = Counter()
    written = Counter()
    skipped_missing_html = 0

    import random

    records = []
    for jsonl_path in args.jsonl:
        with open(jsonl_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))

    if args.per_label is not None:
        random.Random(args.seed).shuffle(records)

    for rec in records:
        label = rec.get("label")
        label_dir = LABEL_DIR.get(label)
        if label_dir is None:
            continue
        if args.per_label is not None and written[label] >= args.per_label:
            continue

        html = rec.get("html")
        if not html:
            skipped_missing_html += 1
            continue

        counts[label] += 1
        dest_dir = out_root / label_dir
        dest_dir.mkdir(parents=True, exist_ok=True)

        slug = slugify(rec.get("netloc", ""))
        sha = (rec.get("sha256") or "")[:8]
        filename = f"{slug}_{sha}.html" if sha else f"{slug}.html"
        (dest_dir / filename).write_text(html, encoding="utf-8")
        written[label] += 1

    print(f"Scanned {sum(counts.values()) + skipped_missing_html} records "
          f"({skipped_missing_html} skipped: no html field)")
    for label, dir_name in LABEL_DIR.items():
        print(f"  {label:8s} -> {written[label]} file(s) written to {out_root / dir_name}")


if __name__ == "__main__":
    main()
