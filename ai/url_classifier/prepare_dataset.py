"""Create a reproducible URL-only PhiUSIIL dataset and EDA reports.

The source CSV mixes URL-derived values with features that require fetching a
webpage. Phisang intentionally never visits submitted destinations, so this
pipeline keeps the raw URL and recomputes only deterministic pre-fetch
features. It also removes known label proxies and remaps the source target to
the less error-prone convention ``is_phishing=1``.

The implementation uses only the Python standard library so the same feature
extraction code can be reused by the API at inference time.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import math
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import SplitResult, urlsplit, urlunsplit


PIPELINE_VERSION = "1.0.0"
DEFAULT_MAX_URL_LENGTH = 4096
PROGRESS_INTERVAL = 50_000
PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT = SCRIPT_DIR / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"
DEFAULT_OUTPUT = (
    SCRIPT_DIR / "datasets" / "processed" / "PhiUSIIL_url_only_clean.csv"
)
DEFAULT_REPORT_JSON = SCRIPT_DIR / "reports" / "PhiUSIIL_eda_summary.json"
DEFAULT_REPORT_MD = SCRIPT_DIR / "reports" / "PhiUSIIL_eda_report.md"

REQUIRED_SOURCE_COLUMNS = {"URL", "label"}

PAGE_DERIVED_COLUMNS = [
    "LineOfCode",
    "LargestLineLength",
    "HasTitle",
    "Title",
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]

LEAKAGE_PRONE_COLUMNS = [
    "FILENAME",
    "URLSimilarityIndex",
    "TLDLegitimateProb",
    "URLCharProb",
    "CharContinuationRate",
    "IsHTTPS",
]

REFERENCE_OR_RECOMPUTED_COLUMNS = [
    "URL",
    "Domain",
    "TLD",
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "label",
]

FEATURE_SCHEMA = [
    ("url", "string", "Normalized HTTP(S) URL; user credentials are removed"),
    ("url_length", "integer", "Number of characters in the normalized URL"),
    ("hostname_length", "integer", "Number of characters in the ASCII hostname"),
    ("path_length", "integer", "Number of characters in the URL path"),
    ("query_length", "integer", "Number of characters in the query string"),
    ("fragment_length", "integer", "Number of characters in the fragment"),
    ("path_depth", "integer", "Count of non-empty path segments"),
    ("host_label_count", "integer", "Count of hostname labels; zero for IP hosts"),
    ("host_dot_count", "integer", "Count of dots in the hostname"),
    ("host_hyphen_count", "integer", "Count of hyphens in the hostname"),
    ("max_host_label_length", "integer", "Length of the longest hostname label"),
    ("tld_length", "integer", "Length of the final hostname label"),
    ("is_ip", "binary", "One when the hostname is an IPv4 or IPv6 literal"),
    ("has_userinfo", "binary", "One when credentials/userinfo existed before cleaning"),
    ("has_punycode", "binary", "One when an ASCII hostname label begins with xn--"),
    ("has_non_ascii", "binary", "One when the original URL contained non-ASCII text"),
    ("letter_count", "integer", "Alphabetic character count"),
    ("letter_ratio", "float", "Alphabetic character count divided by URL length"),
    ("digit_count", "integer", "Numeric character count"),
    ("digit_ratio", "float", "Numeric character count divided by URL length"),
    ("special_count", "integer", "Non-alphanumeric character count"),
    ("special_ratio", "float", "Non-alphanumeric character count divided by URL length"),
    ("dot_count", "integer", "Dot count in the full URL"),
    ("hyphen_count", "integer", "Hyphen count in the full URL"),
    ("underscore_count", "integer", "Underscore count in the full URL"),
    ("slash_count", "integer", "Slash count in the full URL"),
    ("at_count", "integer", "At-sign count in the original URL"),
    ("percent_count", "integer", "Percent-sign count in the full URL"),
    ("percent_encoded_count", "integer", "Count of valid percent-encoded octets"),
    ("equals_count", "integer", "Equals-sign count"),
    ("question_count", "integer", "Question-mark count"),
    ("ampersand_count", "integer", "Ampersand count"),
    ("url_entropy", "float", "Shannon character entropy of the full URL"),
    ("hostname_entropy", "float", "Shannon character entropy of the hostname"),
    ("is_phishing", "binary", "Target: one for phishing, zero for legitimate"),
]

OUTPUT_COLUMNS = [name for name, _kind, _description in FEATURE_SCHEMA]
NUMERIC_FEATURES = [
    name for name, _kind, _description in FEATURE_SCHEMA if name not in {"url", "is_phishing"}
]


class UrlValidationError(ValueError):
    """A URL could not be safely represented by the runtime feature extractor."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class NormalizedUrl:
    url: str
    parts: SplitResult
    hostname: str
    is_ip: bool
    has_userinfo: bool
    has_non_ascii: bool
    original_at_count: int


@dataclass
class NumericAccumulator:
    count: int = 0
    sum_x: float = 0.0
    sum_x2: float = 0.0
    sum_y: float = 0.0
    sum_y2: float = 0.0
    sum_xy: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf

    def add(self, value: float, target: int) -> None:
        self.count += 1
        self.sum_x += value
        self.sum_x2 += value * value
        self.sum_y += target
        self.sum_y2 += target * target
        self.sum_xy += value * target
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    def correlation(self) -> float | None:
        numerator = self.count * self.sum_xy - self.sum_x * self.sum_y
        left = self.count * self.sum_x2 - self.sum_x * self.sum_x
        right = self.count * self.sum_y2 - self.sum_y * self.sum_y
        denominator = left * right
        if denominator <= 0:
            return None
        return numerator / math.sqrt(denominator)

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "min": None if self.count == 0 else round(self.minimum, 6),
            "max": None if self.count == 0 else round(self.maximum, 6),
            "mean": None if self.count == 0 else round(self.sum_x / self.count, 6),
            "correlation_with_is_phishing": (
                None if self.correlation() is None else round(self.correlation() or 0.0, 6)
            ),
        }


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def replace_with_retry(source: Path, destination: Path, attempts: int = 8) -> None:
    """Atomically replace a generated artifact despite transient Windows locks."""
    for attempt in range(attempts):
        try:
            source.replace(destination)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(min(0.25 * (2**attempt), 2.0))


def _is_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def normalize_url(raw_url: str, max_url_length: int = DEFAULT_MAX_URL_LENGTH) -> NormalizedUrl:
    raw = (raw_url or "").strip()
    if not raw:
        raise UrlValidationError("empty_url", "URL is empty")
    if len(raw) > max_url_length:
        raise UrlValidationError(
            "url_too_long", f"URL exceeds the configured {max_url_length}-character limit"
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in raw):
        raise UrlValidationError("control_character", "URL contains a control character")

    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise UrlValidationError("parse_error", "URL could not be parsed") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UrlValidationError("unsupported_scheme", "Only HTTP and HTTPS URLs are supported")

    hostname = parts.hostname
    if not hostname:
        raise UrlValidationError("missing_hostname", "URL has no hostname")
    hostname = hostname.lower().rstrip(".")
    if not hostname or any(character.isspace() for character in hostname):
        raise UrlValidationError("invalid_hostname", "URL hostname is invalid")

    ip_host = _is_ip(hostname)
    if ip_host:
        ascii_host = hostname
    else:
        try:
            ascii_host = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise UrlValidationError("invalid_hostname", "URL hostname is not valid IDNA") from exc

    try:
        port = parts.port
    except ValueError as exc:
        raise UrlValidationError("invalid_port", "URL port is invalid") from exc

    display_host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = display_host if not port or default_port else f"{display_host}:{port}"
    path = parts.path or "/"
    normalized = urlunsplit((scheme, netloc, path, parts.query, parts.fragment))
    if len(normalized) > max_url_length:
        raise UrlValidationError(
            "url_too_long", "Normalized URL exceeds the configured character limit"
        )

    normalized_parts = urlsplit(normalized)
    return NormalizedUrl(
        url=normalized,
        parts=normalized_parts,
        hostname=ascii_host,
        is_ip=ip_host,
        has_userinfo=parts.username is not None or parts.password is not None,
        has_non_ascii=any(ord(character) > 127 for character in raw),
        original_at_count=raw.count("@"),
    )


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_features(parsed: NormalizedUrl, is_phishing: int) -> dict[str, Any]:
    url = parsed.url
    host = parsed.hostname
    path = parsed.parts.path or "/"
    query = parsed.parts.query or ""
    fragment = parsed.parts.fragment or ""
    labels = [] if parsed.is_ip else [label for label in host.split(".") if label]

    letters = sum(character.isalpha() for character in url)
    digits = sum(character.isdigit() for character in url)
    specials = len(url) - letters - digits
    length = len(url)

    return {
        "url": url,
        "url_length": length,
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "fragment_length": len(fragment),
        "path_depth": sum(bool(segment) for segment in path.split("/")),
        "host_label_count": len(labels),
        "host_dot_count": host.count("."),
        "host_hyphen_count": host.count("-"),
        "max_host_label_length": max((len(label) for label in labels), default=len(host)),
        "tld_length": len(labels[-1]) if labels else 0,
        "is_ip": int(parsed.is_ip),
        "has_userinfo": int(parsed.has_userinfo),
        "has_punycode": int(any(label.startswith("xn--") for label in labels)),
        "has_non_ascii": int(parsed.has_non_ascii),
        "letter_count": letters,
        "letter_ratio": round(letters / length, 6),
        "digit_count": digits,
        "digit_ratio": round(digits / length, 6),
        "special_count": specials,
        "special_ratio": round(specials / length, 6),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "at_count": parsed.original_at_count,
        "percent_count": url.count("%"),
        "percent_encoded_count": len(PERCENT_ESCAPE_RE.findall(url)),
        "equals_count": url.count("="),
        "question_count": url.count("?"),
        "ampersand_count": url.count("&"),
        "url_entropy": round(shannon_entropy(url), 6),
        "hostname_entropy": round(shannon_entropy(host), 6),
        "is_phishing": is_phishing,
    }


def quantiles(values: Iterable[int]) -> dict[str, int | None]:
    ordered = sorted(values)
    if not ordered:
        return {name: None for name in ("min", "p50", "p90", "p95", "p99", "max")}

    def at(proportion: float) -> int:
        return ordered[round((len(ordered) - 1) * proportion)]

    return {
        "min": at(0.0),
        "p50": at(0.5),
        "p90": at(0.9),
        "p95": at(0.95),
        "p99": at(0.99),
        "max": at(1.0),
    }


def percentage(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 3) if whole else 0.0


def _source_pattern_stats(row: dict[str, str]) -> dict[str, bool]:
    raw_url = (row.get("URL") or "").strip()
    try:
        parts = urlsplit(raw_url)
        hostname = (parts.hostname or "").lower()
    except ValueError:
        parts = urlsplit("")
        hostname = ""
    try:
        similarity_is_100 = float(row.get("URLSimilarityIndex") or "nan") == 100.0
    except ValueError:
        similarity_is_100 = False
    return {
        "uses_https": parts.scheme.lower() == "https",
        "has_www_prefix": hostname.startswith("www."),
        "has_non_root_path": parts.path not in {"", "/"},
        "has_query": bool(parts.query),
        "url_similarity_index_is_100": similarity_is_100,
    }


def inspect_source(
    input_path: Path, max_url_length: int
) -> tuple[dict[str, Any], dict[str, tuple[int, int]]]:
    labels = Counter()
    invalid_labels = Counter()
    missing = Counter()
    raw_url_counts = Counter()
    normalized_records: dict[str, tuple[int, int]] = {}
    invalid_urls = Counter()
    source_patterns = {0: Counter(), 1: Counter()}
    length_by_source_label: dict[int, list[int]] = {0: [], 1: []}
    tlds_by_source_label: dict[int, Counter[str]] = {0: Counter(), 1: Counter()}
    normalization_changed = 0
    credentials_stripped = 0
    source_columns: list[str] = []

    with input_path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        source_columns = list(reader.fieldnames or [])
        missing_required = sorted(REQUIRED_SOURCE_COLUMNS.difference(source_columns))
        if missing_required:
            raise ValueError(f"Source CSV is missing required columns: {missing_required}")

        for row_number, row in enumerate(reader, start=1):
            if row_number % PROGRESS_INTERVAL == 0:
                print(f"Inspected {row_number:,} source rows")

            for column in source_columns:
                if row.get(column) in {None, ""}:
                    missing[column] += 1

            source_label_text = (row.get("label") or "").strip()
            if source_label_text not in {"0", "1"}:
                invalid_labels[source_label_text or "<empty>"] += 1
                continue
            source_label = int(source_label_text)
            labels[source_label] += 1

            raw_url = (row.get("URL") or "").strip()
            raw_url_counts[raw_url] += 1
            try:
                length_by_source_label[source_label].append(int(float(row.get("URLLength") or len(raw_url))))
            except ValueError:
                length_by_source_label[source_label].append(len(raw_url))
            tlds_by_source_label[source_label][(row.get("TLD") or "<empty>").lower()] += 1
            for pattern, present in _source_pattern_stats(row).items():
                source_patterns[source_label][pattern] += int(present)

            try:
                parsed = normalize_url(raw_url, max_url_length)
            except UrlValidationError as exc:
                invalid_urls[exc.reason] += 1
                continue

            normalization_changed += int(parsed.url != raw_url)
            credentials_stripped += int(parsed.has_userinfo)
            existing_count, existing_mask = normalized_records.get(parsed.url, (0, 0))
            normalized_records[parsed.url] = (
                existing_count + 1,
                existing_mask | (1 << source_label),
            )

    source_rows = sum(labels.values()) + sum(invalid_labels.values())
    exact_duplicate_rows = sum(count - 1 for count in raw_url_counts.values() if count > 1)
    normalized_duplicate_rows = sum(
        count - 1 for count, _mask in normalized_records.values() if count > 1
    )
    conflict_keys = sum(mask == 3 for _count, mask in normalized_records.values())
    conflict_rows = sum(count for count, mask in normalized_records.values() if mask == 3)

    source_summary = {
        "rows": source_rows,
        "columns": len(source_columns),
        "column_names": source_columns,
        "source_label_distribution": {
            "0_phishing": labels[0],
            "1_legitimate": labels[1],
        },
        "invalid_labels": dict(invalid_labels),
        "missing_values": {column: missing[column] for column in source_columns if missing[column]},
        "exact_unique_urls": len(raw_url_counts),
        "exact_duplicate_rows_removed_if_deduplicated": exact_duplicate_rows,
        "normalization": {
            "valid_rows": source_rows - sum(invalid_labels.values()) - sum(invalid_urls.values()),
            "invalid_rows_by_reason": dict(invalid_urls),
            "changed_rows": normalization_changed,
            "credentials_stripped": credentials_stripped,
            "unique_normalized_urls": len(normalized_records),
            "normalized_duplicate_rows_removed": normalized_duplicate_rows,
            "conflicting_normalized_urls": conflict_keys,
            "rows_with_conflicting_normalized_labels": conflict_rows,
        },
        "url_length_quantiles_by_source_label": {
            "0_phishing": quantiles(length_by_source_label[0]),
            "1_legitimate": quantiles(length_by_source_label[1]),
        },
        "source_pattern_counts": {
            str(label): dict(counts) for label, counts in source_patterns.items()
        },
        "top_tlds_by_source_label": {
            "0_phishing": tlds_by_source_label[0].most_common(15),
            "1_legitimate": tlds_by_source_label[1].most_common(15),
        },
    }
    return source_summary, normalized_records


def write_clean_dataset(
    input_path: Path,
    output_path: Path,
    normalized_records: dict[str, tuple[int, int]],
    max_url_length: int,
) -> dict[str, Any]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
    written_urls: set[str] = set()
    clean_labels = Counter()
    clean_url_lengths: dict[int, list[int]] = {0: [], 1: []}
    numeric_stats = {feature: NumericAccumulator() for feature in NUMERIC_FEATURES}

    try:
        with input_path.open(
            "r", encoding="utf-8-sig", errors="replace", newline=""
        ) as source, temporary_path.open("w", encoding="utf-8", newline="") as destination:
            reader = csv.DictReader(source)
            writer = csv.DictWriter(destination, fieldnames=OUTPUT_COLUMNS, lineterminator="\n")
            writer.writeheader()

            for row_number, row in enumerate(reader, start=1):
                if row_number % PROGRESS_INTERVAL == 0:
                    print(f"Processed {row_number:,} source rows")

                source_label_text = (row.get("label") or "").strip()
                if source_label_text not in {"0", "1"}:
                    continue
                try:
                    parsed = normalize_url(row.get("URL") or "", max_url_length)
                except UrlValidationError:
                    continue

                _count, label_mask = normalized_records[parsed.url]
                if label_mask == 3 or parsed.url in written_urls:
                    continue

                source_label = int(source_label_text)
                is_phishing = 1 - source_label
                features = extract_url_features(parsed, is_phishing)
                writer.writerow(features)
                written_urls.add(parsed.url)
                clean_labels[is_phishing] += 1
                clean_url_lengths[is_phishing].append(int(features["url_length"]))
                for feature in NUMERIC_FEATURES:
                    numeric_stats[feature].add(float(features[feature]), is_phishing)

        replace_with_retry(temporary_path, output_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()

    return {
        "rows": len(written_urls),
        "columns": len(OUTPUT_COLUMNS),
        "column_names": OUTPUT_COLUMNS,
        "label_distribution": {
            "0_legitimate": clean_labels[0],
            "1_phishing": clean_labels[1],
        },
        "unique_urls": len(written_urls),
        "url_length_quantiles_by_target": {
            "0_legitimate": quantiles(clean_url_lengths[0]),
            "1_phishing": quantiles(clean_url_lengths[1]),
        },
        "numeric_feature_statistics": {
            feature: accumulator.as_dict() for feature, accumulator in numeric_stats.items()
        },
    }


def _pattern_table(source: dict[str, Any]) -> list[dict[str, Any]]:
    class_counts = {
        0: source["source_label_distribution"]["0_phishing"],
        1: source["source_label_distribution"]["1_legitimate"],
    }
    pattern_counts = source["source_pattern_counts"]
    patterns = sorted(set(pattern_counts.get("0", {})) | set(pattern_counts.get("1", {})))
    return [
        {
            "pattern": pattern,
            "phishing_count": pattern_counts.get("0", {}).get(pattern, 0),
            "phishing_percent": percentage(
                pattern_counts.get("0", {}).get(pattern, 0), class_counts[0]
            ),
            "legitimate_count": pattern_counts.get("1", {}).get(pattern, 0),
            "legitimate_percent": percentage(
                pattern_counts.get("1", {}).get(pattern, 0), class_counts[1]
            ),
        }
        for pattern in patterns
    ]


def build_summary(
    input_path: Path,
    output_path: Path,
    source: dict[str, Any],
    cleaned: dict[str, Any],
    max_url_length: int,
) -> dict[str, Any]:
    expected_page_columns = [
        column for column in PAGE_DERIVED_COLUMNS if column in source["column_names"]
    ]
    expected_leakage_columns = [
        column for column in LEAKAGE_PRONE_COLUMNS if column in source["column_names"]
    ]
    expected_recomputed_columns = [
        column for column in REFERENCE_OR_RECOMPUTED_COLUMNS if column in source["column_names"]
    ]
    correlations = {
        feature: details["correlation_with_is_phishing"]
        for feature, details in cleaned["numeric_feature_statistics"].items()
    }
    strongest_correlations = sorted(
        (
            {"feature": feature, "correlation_with_is_phishing": correlation}
            for feature, correlation in correlations.items()
            if correlation is not None
        ),
        key=lambda item: abs(item["correlation_with_is_phishing"]),
        reverse=True,
    )

    return {
        "pipeline_version": PIPELINE_VERSION,
        "configuration": {
            "max_url_length": max_url_length,
            "supported_schemes": ["http", "https"],
            "target_mapping": {
                "source_label_0": "phishing",
                "source_label_1": "legitimate",
                "output_is_phishing_0": "legitimate",
                "output_is_phishing_1": "phishing",
            },
        },
        "input": {
            "path": str(input_path),
            "sha256": file_sha256(input_path),
            **source,
        },
        "output": {
            "path": str(output_path),
            "sha256": file_sha256(output_path),
            **cleaned,
        },
        "cleaning_rules": {
            "deduplication_key": "normalized full URL",
            "conflicting_label_policy": "drop every normalized URL with conflicting labels",
            "userinfo_policy": "remove credentials from URL and retain has_userinfo binary feature",
            "fragment_policy": "retain for URL-string classification",
            "page_derived_columns_removed": expected_page_columns,
            "leakage_prone_columns_removed": expected_leakage_columns,
            "reference_or_recomputed_columns": expected_recomputed_columns,
        },
        "feature_schema": [
            {"name": name, "type": kind, "description": description}
            for name, kind, description in FEATURE_SCHEMA
        ],
        "eda": {
            "source_pattern_comparison": _pattern_table(source),
            "strongest_clean_feature_correlations": strongest_correlations,
            "warnings": [
                "The source data has perfect or near-perfect collection shortcuts: every legitimate row uses HTTPS, begins with www, has no non-root path/query, and has URLSimilarityIndex=100.",
                "The cleaned CSV removes direct proxy columns, but length and path-related features remain source-biased because the legitimate samples are homepages.",
                "Use a registered-domain-grouped split and an independently sourced test dataset; random row splits are not credible for this dataset.",
                "The cleaned target is binary phishing-vs-legitimate and must not be used to learn a malware class.",
            ],
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    source = summary["input"]
    output = summary["output"]
    patterns = summary["eda"]["source_pattern_comparison"]
    correlations = summary["eda"]["strongest_clean_feature_correlations"][:12]
    invalid = source["normalization"]["invalid_rows_by_reason"]

    lines = [
        "# PhiUSIIL URL-only EDA and cleaning report",
        "",
        f"Pipeline version: {summary['pipeline_version']}",
        "",
        "## Dataset flow",
        "",
        "| Measure | Value |",
        "|---|---:|",
        f"| Source rows | {source['rows']:,} |",
        f"| Source columns | {source['columns']:,} |",
        f"| Exact duplicate rows | {source['exact_duplicate_rows_removed_if_deduplicated']:,} |",
        f"| Invalid rows removed | {sum(invalid.values()):,} |",
        f"| Normalized duplicate rows removed | {source['normalization']['normalized_duplicate_rows_removed']:,} |",
        f"| Normalized URL keys with conflicting labels | {source['normalization']['conflicting_normalized_urls']:,} |",
        f"| Rows removed for normalized-label conflicts | {source['normalization']['rows_with_conflicting_normalized_labels']:,} |",
        f"| Clean rows | {output['rows']:,} |",
        f"| Clean columns | {output['columns']:,} |",
        "",
        "## Labels",
        "",
        "The source uses 0 for phishing and 1 for legitimate. The cleaned dataset intentionally uses is_phishing=1 for phishing and is_phishing=0 for legitimate.",
        "",
        "| Dataset | Legitimate | Phishing |",
        "|---|---:|---:|",
        f"| Source | {source['source_label_distribution']['1_legitimate']:,} | {source['source_label_distribution']['0_phishing']:,} |",
        f"| Clean | {output['label_distribution']['0_legitimate']:,} | {output['label_distribution']['1_phishing']:,} |",
        "",
        "## Source collection-bias checks",
        "",
        "| Pattern | Phishing | Legitimate |",
        "|---|---:|---:|",
    ]
    for row in patterns:
        lines.append(
            f"| {row['pattern']} | {row['phishing_percent']:.3f}% | {row['legitimate_percent']:.3f}% |"
        )

    lines.extend(
        [
            "",
            "These differences are dataset-source shortcuts, not proof of phishing. A random row split will substantially overstate generalization.",
            "",
            "## Cleaning and preprocessing",
            "",
            f"- Accepted HTTP and HTTPS URLs up to {summary['configuration']['max_url_length']:,} characters.",
            "- Lowercased and IDNA-normalized hostnames and removed default ports.",
            "- Removed URL user credentials while retaining a has_userinfo risk feature.",
            "- Removed destination-page features because Phisang never fetches submitted pages.",
            "- Removed direct label proxies and corpus-derived probability fields.",
            "- Recomputed every output feature from the URL using this pipeline.",
            "- Deduplicated by normalized URL and dropped any normalized URL with conflicting labels.",
            "",
            "### Removed feature groups",
            "",
            f"- Page-derived columns ({len(summary['cleaning_rules']['page_derived_columns_removed'])}): "
            + ", ".join(summary["cleaning_rules"]["page_derived_columns_removed"]),
            f"- Leakage-prone columns ({len(summary['cleaning_rules']['leakage_prone_columns_removed'])}): "
            + ", ".join(summary["cleaning_rules"]["leakage_prone_columns_removed"]),
            "",
            "## Strongest cleaned-feature correlations",
            "",
            "Correlation is descriptive only; large values may still reflect collection bias.",
            "",
            "| Feature | Pearson correlation with is_phishing |",
            "|---|---:|",
        ]
    )
    for item in correlations:
        lines.append(
            f"| {item['feature']} | {item['correlation_with_is_phishing']:.6f} |"
        )

    lines.extend(
        [
            "",
            "## Training guidance",
            "",
            "- Split by public-suffix-aware registered domain, never by random row.",
            "- Validate against a second, independently sourced and more recent dataset.",
            "- Add legitimate deep links, query strings, and non-www hosts before claiming real-world performance.",
            "- Treat the target as phishing risk only. URLhaus remains the known-malware signal.",
            "- Do not present an uncalibrated model probability as confidence.",
            "",
            "## Reproducibility",
            "",
            f"- Input SHA-256: {source['sha256']}",
            f"- Output SHA-256: {output['sha256']}",
            "",
        ]
    )
    return "\n".join(lines)


def run_pipeline(
    input_path: Path,
    output_path: Path,
    report_json_path: Path,
    report_md_path: Path,
    max_url_length: int,
) -> dict[str, Any]:
    if not input_path.exists():
        raise FileNotFoundError(f"Input dataset does not exist: {input_path}")

    print(f"Inspecting {input_path}")
    source_summary, normalized_records = inspect_source(input_path, max_url_length)
    print(f"Writing cleaned dataset to {output_path}")
    clean_summary = write_clean_dataset(
        input_path, output_path, normalized_records, max_url_length
    )
    summary = build_summary(
        input_path, output_path, source_summary, clean_summary, max_url_length
    )

    report_json_path.parent.mkdir(parents=True, exist_ok=True)
    report_md_path.parent.mkdir(parents=True, exist_ok=True)
    report_json_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    report_md_path.write_text(render_markdown(summary), encoding="utf-8")
    print(f"Wrote {clean_summary['rows']:,} clean rows")
    print(f"EDA JSON: {report_json_path}")
    print(f"EDA Markdown: {report_md_path}")
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a cleaned URL-only PhiUSIIL CSV and EDA reports."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report-json", type=Path, default=DEFAULT_REPORT_JSON)
    parser.add_argument("--report-md", type=Path, default=DEFAULT_REPORT_MD)
    parser.add_argument(
        "--max-url-length", type=int, default=DEFAULT_MAX_URL_LENGTH, metavar="N"
    )
    args = parser.parse_args()
    if args.max_url_length < 1:
        parser.error("--max-url-length must be positive")
    return args


def main() -> None:
    args = parse_args()
    run_pipeline(
        input_path=args.input.resolve(),
        output_path=args.output.resolve(),
        report_json_path=args.report_json.resolve(),
        report_md_path=args.report_md.resolve(),
        max_url_length=args.max_url_length,
    )


if __name__ == "__main__":
    main()
