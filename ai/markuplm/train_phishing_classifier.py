"""Fine-tune MarkupLM for benign/phishing HTML page classification.

Trains `MarkupLMForSequenceClassification` on a stratified sample of the
PhreshPhish dataset (CC BY 4.0, anti-phishing research use only).

This is the batch/long-run counterpart to `train_html_phishing_classifier.ipynb`:
same pipeline, but loggable, resumable from a cached sample, and safe to run in
the background.

Run from the repository root:

    ai/markuplm/.venv/bin/python -B ai/markuplm/train_phishing_classifier.py

Guardrails that matter for this dataset:

1. The raw sample is cached to disk, so re-runs never re-stream the dataset.
2. Streaming is shuffled (shard order + buffer) so the sample is not just the
   head of the parquet files.
3. Pages are deduplicated by content hash, and train/val are split by netloc so
   the same site never lands on both sides. Phishing kits are heavily reused, so
   a naive split reports accuracy that does not survive contact with new sites.
4. The held-out test set comes from PhreshPhish's own `test` split, not from our
   training pool.
5. The checkpoint that is kept is the best epoch by validation F1, not the last.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import pyarrow.parquet as pq
import torch
from huggingface_hub import hf_hub_download
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score
from torch.optim import AdamW
from torch.utils.data import DataLoader, Dataset
from tqdm.auto import tqdm
from transformers import (
    MarkupLMFeatureExtractor,
    MarkupLMForSequenceClassification,
    MarkupLMProcessor,
    get_linear_schedule_with_warmup,
)

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_DIR = SCRIPT_DIR / "datasets" / "phreshphish_sample"
ARTIFACT_ROOT = SCRIPT_DIR / "artifacts"
REPORT_DIR = SCRIPT_DIR / "reports"

BASE_MODEL = "microsoft/markuplm-base"
DATASET_ID = "phreshphish/phreshphish"

# The dataset ships as ~500MB parquet shards (~10k pages each). Pulling a few
# shards gives random access to plenty of pages without streaming all 36.6GB.
SHARD_COUNTS = {"train": 56, "test": 21}

ID2LABEL = {0: "benign", 1: "phishing"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}
SOURCE_LABEL_TO_ID = {"benign": 0, "phish": 1}

# Pages far outside this range are placeholders or obfuscated mega-bundles; both
# cost parsing time out of proportion to what the model can learn from them.
MIN_HTML_CHARS = 200
MAX_HTML_CHARS = 400_000

logger = logging.getLogger("markuplm-train")

# Progress bars are for a human at a terminal. When output is redirected to a
# log file they would bury the phase lines that watch_progress.py reads back,
# so they turn themselves off.
SHOW_BARS = sys.stdout.isatty()


def bar(iterable, desc: str, **kwargs):
    return tqdm(iterable, desc=desc, disable=not SHOW_BARS, leave=False, **kwargs)


@dataclass
class Config:
    train_per_class: int = 3000
    val_per_class: int = 400
    test_per_class: int = 400
    epochs: int = 3
    batch_size: int = 8
    learning_rate: float = 2e-5
    warmup_ratio: float = 0.1
    max_length: int = 512
    seed: int = 42
    train_shards: int = 3
    test_shards: int = 1
    num_workers: int = 4
    version: str = "v1"
    refresh_cache: bool = False
    device: str = field(default="auto")

    @property
    def artifact_dir(self) -> Path:
        return ARTIFACT_ROOT / f"phishing-html-classifier-{self.version}"

    @property
    def cache_dir(self) -> Path:
        # Keyed by sample size: a cache built for a smaller run must never be
        # silently reused by a larger one.
        return CACHE_DIR / f"train{self.train_per_class}_val{self.val_per_class}_test{self.test_per_class}"


# --------------------------------------------------------------------------- #
# Sampling
# --------------------------------------------------------------------------- #


def netloc_of(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except ValueError:
        return ""


def pick_shards(split: str, count: int) -> list[str]:
    """Evenly spaced shards across the split, so the sample spans crawl batches.

    Shard 000 is a small partial shard (1k rows); the rest hold ~10k rows each.
    """
    total = SHARD_COUNTS[split]
    if count >= total:
        chosen = range(1, total)
    else:
        stride = max((total - 1) // count, 1)
        chosen = [1 + i * stride for i in range(count) if 1 + i * stride < total]
    return [f"data/{split}-{index:03d}.parquet" for index in chosen]


def sample_from_shard(path: Path, per_class: int, cfg: Config, seen_hashes: set[str]) -> list[dict]:
    """Randomly sample up to `per_class` rows per label from one local shard."""
    parquet_file = pq.ParquetFile(path)
    labels = pq.read_table(path, columns=["label"]).column("label").to_pylist()

    # Choose candidate row indices up front, oversampling so the HTML-size
    # filter and dedupe below don't leave us short.
    rng = random.Random(cfg.seed)
    wanted: set[int] = set()
    for label in ("benign", "phish"):
        indices = [i for i, value in enumerate(labels) if value == label]
        rng.shuffle(indices)
        wanted.update(indices[: int(per_class * 1.6)])

    remaining = {"benign": per_class, "phish": per_class}
    collected: list[dict] = []
    row_index = 0

    for batch in parquet_file.iter_batches(batch_size=256):
        rows = batch.to_pylist()
        for row in rows:
            current, row_index = row_index, row_index + 1
            if current not in wanted:
                continue
            label = row["label"]
            if remaining.get(label, 0) <= 0:
                continue
            html = row["html"] or ""
            if not (MIN_HTML_CHARS <= len(html) <= MAX_HTML_CHARS):
                continue
            digest = row["sha256"]
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            collected.append(
                {
                    "sha256": digest,
                    "url": row["url"],
                    "netloc": netloc_of(row["url"]),
                    "label": label,
                    "label_id": SOURCE_LABEL_TO_ID[label],
                    "html": html,
                }
            )
            remaining[label] -= 1
        if all(value <= 0 for value in remaining.values()):
            break

    return collected


def sample_split(split: str, per_class: int, shard_count: int, cfg: Config, seen_hashes: set[str]) -> list[dict]:
    """Download a few shards of `split` and sample `per_class` rows per label."""
    shards = pick_shards(split, shard_count)
    per_shard = -(-per_class // len(shards))  # ceil, so shards share the quota
    collected: list[dict] = []
    started = time.monotonic()

    for shard in shards:
        logger.info("  %s: downloading %s", split, shard)
        local_path = Path(hf_hub_download(DATASET_ID, shard, repo_type="dataset"))
        rows = sample_from_shard(local_path, per_shard, cfg, seen_hashes)
        counts = defaultdict(int)
        for row in rows:
            counts[row["label"]] += 1
        logger.info("  %s: %s -> %d rows %s", split, shard, len(rows), dict(counts))
        collected.extend(rows)

    totals = defaultdict(int)
    for row in collected:
        totals[row["label"]] += 1
    logger.info(
        "  %s: %d rows total %s in %.1fs", split, len(collected), dict(totals), time.monotonic() - started
    )
    return collected


def split_by_netloc(rows: list[dict], val_per_class: int, seed: int) -> tuple[list[dict], list[dict]]:
    """Hold out whole netlocs for validation so no site spans both sides."""
    by_netloc: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_netloc[row["netloc"] or row["sha256"]].append(row)

    netlocs = sorted(by_netloc)
    random.Random(seed).shuffle(netlocs)

    val: list[dict] = []
    val_counts = {0: 0, 1: 0}
    val_netlocs: set[str] = set()

    for netloc in netlocs:
        group = by_netloc[netloc]
        # Only take a netloc if every page in it still fits under the quota.
        label_ids = {row["label_id"] for row in group}
        if any(val_counts[label_id] + len(group) > val_per_class for label_id in label_ids):
            continue
        val.extend(group)
        val_netlocs.add(netloc)
        for row in group:
            val_counts[row["label_id"]] += 1
        if all(count >= val_per_class for count in val_counts.values()):
            break

    train = [row for row in rows if (row["netloc"] or row["sha256"]) not in val_netlocs]
    return train, val


def load_or_build_sample(cfg: Config) -> dict[str, list[dict]]:
    cache_dir = cfg.cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_files = {name: cache_dir / f"{name}.jsonl" for name in ("train", "val", "test")}

    if not cfg.refresh_cache and all(path.exists() for path in cache_files.values()):
        splits = {}
        for name, path in cache_files.items():
            with path.open() as handle:
                splits[name] = [json.loads(line) for line in handle]
        logger.info(
            "Loaded cached sample: train=%d val=%d test=%d (delete %s to re-sample)",
            len(splits["train"]),
            len(splits["val"]),
            len(splits["test"]),
            cache_dir,
        )
        return splits

    logger.info("Building sample from PhreshPhish parquet shards (downloads are cached by huggingface_hub)")
    seen_hashes: set[str] = set()

    pool = sample_split(
        "train", cfg.train_per_class + cfg.val_per_class, cfg.train_shards, cfg, seen_hashes
    )
    train_rows, val_rows = split_by_netloc(pool, cfg.val_per_class, cfg.seed)
    test_rows = sample_split("test", cfg.test_per_class, cfg.test_shards, cfg, seen_hashes)

    splits = {"train": train_rows, "val": val_rows, "test": test_rows}
    for name, rows in splits.items():
        with cache_files[name].open("w") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
    logger.info("Cached sample to %s", cache_dir)
    return splits


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #


def extract_nodes(rows: list[dict], split_name: str) -> list[dict]:
    """Turn raw HTML into the (nodes, xpaths) pairs MarkupLM consumes."""
    feature_extractor = MarkupLMFeatureExtractor()
    examples: list[dict] = []
    failures = 0
    started = time.monotonic()

    for index, row in enumerate(bar(rows, f"parse {split_name}"), start=1):
        try:
            encoding = feature_extractor(row["html"])
        except Exception:  # malformed real-world markup; count and move on
            failures += 1
            continue
        nodes = encoding["nodes"][0]
        xpaths = encoding["xpaths"][0]
        if not nodes:
            failures += 1
            continue
        examples.append(
            {
                "nodes": [nodes],
                "xpaths": [xpaths],
                "label_id": row["label_id"],
                "url": row["url"],
            }
        )
        if index % 1000 == 0:
            logger.info("  %s: parsed %d/%d pages", split_name, index, len(rows))

    counts = defaultdict(int)
    for example in examples:
        counts[ID2LABEL[example["label_id"]]] += 1
    logger.info(
        "  %s: %d usable pages %s (%d skipped) in %.1fs",
        split_name,
        len(examples),
        dict(counts),
        failures,
        time.monotonic() - started,
    )
    return examples


class HtmlPhishingDataset(Dataset):
    """One HTML page -> one benign/phishing label."""

    def __init__(self, data: list[dict], processor: MarkupLMProcessor, max_length: int):
        self.data = data
        self.processor = processor
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int):
        item = self.data[idx]
        encoding = self.processor(
            nodes=item["nodes"],
            xpaths=item["xpaths"],
            truncation=True,
            padding="max_length",
            max_length=self.max_length,
            return_tensors="pt",
        )
        encoding = {k: v.squeeze(0) for k, v in encoding.items()}
        encoding["labels"] = torch.tensor(item["label_id"], dtype=torch.long)
        return encoding


# --------------------------------------------------------------------------- #
# Train / evaluate
# --------------------------------------------------------------------------- #


def pick_device(requested: str) -> torch.device:
    if requested != "auto":
        return torch.device(requested)
    if torch.cuda.is_available():
        return torch.device("cuda")
    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")


@torch.no_grad()
def evaluate(model, dataloader, device) -> dict:
    model.eval()
    probs: list[float] = []
    labels: list[int] = []
    for batch in bar(dataloader, "eval"):
        inputs = {k: v.to(device) for k, v in batch.items()}
        logits = model(**inputs).logits
        probs.extend(torch.softmax(logits, dim=-1)[:, 1].cpu().tolist())
        labels.extend(batch["labels"].tolist())
    return {"probs": probs, "labels": labels}


def metrics_at(probs: list[float], labels: list[int], threshold: float) -> dict:
    preds = [1 if p >= threshold else 0 for p in probs]
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average="binary", pos_label=1, zero_division=0
    )
    accuracy = sum(int(p == l) for p, l in zip(preds, labels)) / max(len(labels), 1)
    return {
        "threshold": round(threshold, 3),
        "accuracy": round(accuracy, 4),
        "precision_phishing": round(float(precision), 4),
        "recall_phishing": round(float(recall), 4),
        "f1_phishing": round(float(f1), 4),
        "n": len(labels),
    }


def best_threshold(probs: list[float], labels: list[int]) -> tuple[float, dict]:
    best = (0.5, metrics_at(probs, labels, 0.5))
    for step in range(5, 100, 5):
        threshold = step / 100
        candidate = metrics_at(probs, labels, threshold)
        if candidate["f1_phishing"] > best[1]["f1_phishing"]:
            best = (threshold, candidate)
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train-per-class", type=int, default=Config.train_per_class)
    parser.add_argument("--val-per-class", type=int, default=Config.val_per_class)
    parser.add_argument("--test-per-class", type=int, default=Config.test_per_class)
    parser.add_argument("--epochs", type=int, default=Config.epochs)
    parser.add_argument("--batch-size", type=int, default=Config.batch_size)
    parser.add_argument("--learning-rate", type=float, default=Config.learning_rate)
    parser.add_argument("--train-shards", type=int, default=Config.train_shards)
    parser.add_argument("--test-shards", type=int, default=Config.test_shards)
    parser.add_argument("--version", default=Config.version)
    parser.add_argument("--device", default=Config.device)
    parser.add_argument("--refresh-cache", action="store_true")
    args = parser.parse_args()

    cfg = Config(
        train_per_class=args.train_per_class,
        val_per_class=args.val_per_class,
        test_per_class=args.test_per_class,
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        train_shards=args.train_shards,
        test_shards=args.test_shards,
        version=args.version,
        device=args.device,
        refresh_cache=args.refresh_cache,
    )

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    torch.manual_seed(cfg.seed)
    random.seed(cfg.seed)

    logger.info("Config: %s", {k: v for k, v in vars(cfg).items()})

    splits = load_or_build_sample(cfg)
    logger.info("Extracting nodes and xpaths from raw HTML")
    data = {name: extract_nodes(rows, name) for name, rows in splits.items()}

    processor = MarkupLMProcessor.from_pretrained(BASE_MODEL)
    processor.parse_html = False

    loaders = {}
    for name, examples in data.items():
        dataset = HtmlPhishingDataset(examples, processor, cfg.max_length)
        loaders[name] = DataLoader(
            dataset,
            batch_size=cfg.batch_size,
            shuffle=(name == "train"),
            num_workers=cfg.num_workers,
            persistent_workers=cfg.num_workers > 0,
        )

    device = pick_device(cfg.device)
    logger.info("Device: %s", device)

    model = MarkupLMForSequenceClassification.from_pretrained(
        BASE_MODEL, num_labels=2, id2label=ID2LABEL, label2id=LABEL2ID
    ).to(device)

    optimizer = AdamW(model.parameters(), lr=cfg.learning_rate)
    total_steps = len(loaders["train"]) * cfg.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=int(total_steps * cfg.warmup_ratio),
        num_training_steps=total_steps,
    )

    cfg.artifact_dir.mkdir(parents=True, exist_ok=True)
    history: list[dict] = []
    best_f1 = -1.0
    best_epoch = -1

    for epoch in range(cfg.epochs):
        model.train()
        running_loss = 0.0
        epoch_started = time.monotonic()

        progress = bar(loaders["train"], f"epoch {epoch + 1}/{cfg.epochs}")
        for step, batch in enumerate(progress, start=1):
            inputs = {k: v.to(device) for k, v in batch.items()}
            optimizer.zero_grad()
            outputs = model(**inputs)
            outputs.loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            scheduler.step()
            running_loss += outputs.loss.item()

            if SHOW_BARS:
                progress.set_postfix(loss=f"{running_loss / step:.4f}")

            if step % 50 == 0:
                logger.info(
                    "  epoch %d step %d/%d loss=%.4f (%.1f min elapsed)",
                    epoch,
                    step,
                    len(loaders["train"]),
                    running_loss / step,
                    (time.monotonic() - epoch_started) / 60,
                )

        val_raw = evaluate(model, loaders["val"], device)
        val_metrics = metrics_at(val_raw["probs"], val_raw["labels"], 0.5)
        val_auc = roc_auc_score(val_raw["labels"], val_raw["probs"]) if len(set(val_raw["labels"])) > 1 else float("nan")
        entry = {
            "epoch": epoch,
            "train_loss": round(running_loss / len(loaders["train"]), 4),
            "val": val_metrics,
            "val_roc_auc": round(float(val_auc), 4),
            "minutes": round((time.monotonic() - epoch_started) / 60, 1),
        }
        history.append(entry)
        logger.info("epoch %d done: %s", epoch, entry)

        if val_metrics["f1_phishing"] > best_f1:
            best_f1 = val_metrics["f1_phishing"]
            best_epoch = epoch
            model.save_pretrained(cfg.artifact_dir)
            processor.save_pretrained(cfg.artifact_dir)
            logger.info("  new best val F1=%.4f -> checkpoint saved", best_f1)

    logger.info("Best epoch: %d (val F1=%.4f). Reloading that checkpoint for test.", best_epoch, best_f1)
    model = MarkupLMForSequenceClassification.from_pretrained(cfg.artifact_dir).to(device)

    val_raw = evaluate(model, loaders["val"], device)
    tuned_threshold, tuned_val_metrics = best_threshold(val_raw["probs"], val_raw["labels"])

    test_raw = evaluate(model, loaders["test"], device)
    test_default = metrics_at(test_raw["probs"], test_raw["labels"], 0.5)
    test_tuned = metrics_at(test_raw["probs"], test_raw["labels"], tuned_threshold)
    test_auc = (
        roc_auc_score(test_raw["labels"], test_raw["probs"]) if len(set(test_raw["labels"])) > 1 else float("nan")
    )
    matrix = confusion_matrix(
        test_raw["labels"], [1 if p >= tuned_threshold else 0 for p in test_raw["probs"]]
    ).tolist()

    summary = {
        "base_model": BASE_MODEL,
        "task": "sequence-classification",
        "dataset": DATASET_ID,
        "dataset_license": "CC BY 4.0 (anti-phishing research use)",
        "id2label": ID2LABEL,
        "config": {k: v for k, v in vars(cfg).items() if k != "device"},
        "counts": {name: len(examples) for name, examples in data.items()},
        "history": history,
        "best_epoch": best_epoch,
        "val_threshold_tuned": tuned_val_metrics,
        "test_at_0.5": test_default,
        "test_at_tuned_threshold": test_tuned,
        "test_roc_auc": round(float(test_auc), 4),
        "test_confusion_matrix_tn_fp_fn_tp": matrix,
    }

    (cfg.artifact_dir / "metadata.json").write_text(json.dumps(summary, indent=2))
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / f"training_{cfg.version}.json").write_text(json.dumps(summary, indent=2))

    logger.info("TEST @0.5: %s", test_default)
    logger.info("TEST @%.2f: %s", tuned_threshold, test_tuned)
    logger.info("TEST ROC-AUC: %.4f", test_auc)
    logger.info("Confusion matrix [[TN, FP], [FN, TP]]: %s", matrix)
    logger.info("Artifact: %s", cfg.artifact_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
