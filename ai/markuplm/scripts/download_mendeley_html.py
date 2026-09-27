"""Download the Mendeley n96ncsr5g4 phishing corpus and write it out as .html files.

The corpus ships as one 465 MB JSON array inside ealvaradob/phishing-dataset
(field `text` holds raw HTML, `label` is 1 for phishing). It needs
trust_remote_code through load_dataset, which datasets>=4 removed, so the file is
fetched directly instead.

This is an out-of-distribution test set: the classifier was trained on
PhreshPhish, so scores here measure whether it generalises beyond that corpus.

Usage:
    python scripts/download_mendeley_html.py --per-class 150
    python scripts/download_mendeley_html.py --per-class 400 --out-name mendeley_large
"""

import argparse
import hashlib
import json
import random
from pathlib import Path

REPO_ID = "ealvaradob/phishing-dataset"
FILENAME = "webs.json"
LABEL_DIRS = {1: "phishing", 0: "benign"}


def load_seen_hashes(manifest: Path) -> set:
    """sha256 of pages an artifact already trained on, so they can be excluded."""
    if not manifest.is_file():
        return set()
    seen = set()
    with manifest.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                digest = json.loads(line).get("sha256")
                if digest:
                    seen.add(digest)
    return seen


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--per-class", type=int, default=150,
                        help="Pages to write per label (default: 150)")
    parser.add_argument("--out-name", default="mendeley",
                        help="Folder created under examples/ (default: mendeley)")
    parser.add_argument("--seed", type=int, default=42, help="Sampling seed")
    parser.add_argument("--exclude-manifest",
                        default="artifacts/phishing-html-classifier-v1/split_manifest.jsonl",
                        help="Artifact manifest whose pages must not appear here")
    parser.add_argument("--min-chars", type=int, default=200,
                        help="Skip pages shorter than this (default: 200)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    out_root = root / "examples" / args.out_name
    if out_root.exists() and any(out_root.rglob("*.html")):
        parser.error(f"{out_root} already holds .html files; remove it or pass a new --out-name")

    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        raise SystemExit("huggingface_hub is required: pip install huggingface_hub")

    print(f"Fetching {FILENAME} from {REPO_ID} (~465 MB, cached after the first run)...")
    path = hf_hub_download(REPO_ID, FILENAME, repo_type="dataset")

    print("Parsing (needs roughly 2 GB of RAM)...")
    with open(path, encoding="utf-8") as handle:
        rows = json.load(handle)
    print(f"  {len(rows):,} pages in the corpus")

    seen = load_seen_hashes(root / args.exclude_manifest)
    print(f"  {len(seen):,} hashes excluded via {args.exclude_manifest}")

    random.Random(args.seed).shuffle(rows)
    written = {0: 0, 1: 0}
    skipped_short = skipped_seen = skipped_dupe = 0
    emitted = set()

    for row in rows:
        label = row.get("label")
        if label not in LABEL_DIRS or written[label] >= args.per_class:
            if all(written[k] >= args.per_class for k in LABEL_DIRS):
                break
            continue
        html = row.get("text") or ""
        if len(html) < args.min_chars:
            skipped_short += 1
            continue
        digest = hashlib.sha256(html.encode("utf-8", "ignore")).hexdigest()
        if digest in seen:
            skipped_seen += 1
            continue
        if digest in emitted:
            skipped_dupe += 1
            continue
        emitted.add(digest)

        dest_dir = out_root / LABEL_DIRS[label]
        dest_dir.mkdir(parents=True, exist_ok=True)
        (dest_dir / f"{args.out_name}_{digest[:12]}.html").write_text(html, encoding="utf-8")
        written[label] += 1

    print(f"\nwrote {written[0]} benign + {written[1]} phishing to {out_root}")
    print(f"skipped: {skipped_short} too short, {skipped_seen} already seen in training, "
          f"{skipped_dupe} duplicates")
    if min(written.values()) < args.per_class:
        print("NOTE: fewer pages than requested survived filtering.")


if __name__ == "__main__":
    main()
