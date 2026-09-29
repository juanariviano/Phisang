"""Page phishing classifiers, loaded once and served under a lock.

Two artifact layouts are understood. A MarkupLM folder mirrors the inference
contract of ai/markuplm/smoke_test.ipynb; a Laya folder (one holding
rl_agent_config.json, e.g. laya_v2) mirrors finetune_laya_phishing_kaggle.ipynb.
Either way the same preprocessing metadata is applied, so API scores match the
notebooks'.
"""

import json
import math
import sys
import threading
from pathlib import Path

import torch
from bs4 import BeautifulSoup, Comment
from transformers import (MarkupLMFeatureExtractor, MarkupLMForSequenceClassification,
                          MarkupLMProcessor)


class ModelUnavailable(Exception):
    """The artifact could not be loaded."""


def _load_metadata(model_dir: Path) -> dict:
    metadata_path = model_dir / "metadata.json"
    return (json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata_path.is_file() else {})


def _clean_markup(html: str, preprocessing: dict) -> str:
    soup = BeautifulSoup(html[:int(preprocessing["parse_char_budget"])], "html.parser")
    for element in soup.find_all(preprocessing["strip_tags"]):
        element.decompose()
    if preprocessing.get("strip_comments", False):
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            comment.extract()
    return str(soup)


def load_classifier(model_dir):
    """Picks the loader that fits the artifact's layout."""
    model_dir = Path(model_dir).resolve()
    if (model_dir / "rl_agent_config.json").is_file():
        return LayaClassifier(model_dir)
    return Classifier(model_dir)


class Classifier:
    def __init__(self, model_dir: Path):
        model_dir = Path(model_dir).resolve()
        if not (model_dir / "config.json").is_file():
            raise ModelUnavailable(f"no saved model at {model_dir}")
        self.model_dir = model_dir

        metadata = _load_metadata(model_dir)
        self._preprocessing = metadata.get("preprocessing")
        if self._preprocessing is not None and "strip_tags" not in self._preprocessing:
            raise ModelUnavailable("artifact uses an unrecognised preprocessing schema")

        # CPU only: a public endpoint should not depend on an accelerator being
        # free, and MarkupLM-base inference on one page is cheap enough.
        self.device = torch.device("cpu")
        self.processor = MarkupLMProcessor.from_pretrained(model_dir, local_files_only=True)
        self.processor.parse_html = False
        self.feature_extractor = MarkupLMFeatureExtractor()
        self.model = MarkupLMForSequenceClassification.from_pretrained(
            model_dir, local_files_only=True, use_safetensors=True, dtype=torch.float32,
        ).to(self.device).eval()

        self.id2label = {int(k): v for k, v in self.model.config.id2label.items()}
        phishing_ids = [k for k, v in self.id2label.items()
                        if v.lower() in {"phishing", "phish"}]
        if self.model.config.num_labels != 2 or len(phishing_ids) != 1:
            raise ModelUnavailable(f"expected two classes including phishing; got {self.id2label}")
        self.phishing_id = phishing_ids[0]
        self.benign_id = 1 - self.phishing_id

        inference = metadata.get("inference", {})
        self.temperature = float(inference.get("temperature", 1.0))
        self.threshold = float(inference.get("operating_threshold", 0.5))
        if not math.isfinite(self.temperature) or self.temperature <= 0:
            raise ModelUnavailable("invalid temperature in saved metadata")
        if not math.isfinite(self.threshold) or not 0 <= self.threshold <= 1:
            raise ModelUnavailable("invalid threshold in saved metadata")
        self.max_tokens = int((self._preprocessing or {}).get("max_tokens", 512))
        self.test_metrics = metadata.get("test_metrics", {})

        # One model instance, many request threads: serialise the forward pass.
        self._lock = threading.Lock()

    def _extract_page(self, html: str) -> dict:
        if self._preprocessing is not None:
            encoding = self.feature_extractor(_clean_markup(html, self._preprocessing))
            pairs = [(node.strip(), xpath)
                     for node, xpath in zip(encoding["nodes"][0], encoding["xpaths"][0])
                     if node.strip()]
            if not pairs:
                raise ValueError("no usable text nodes")
            nodes, xpaths = zip(*pairs)
            return {"nodes": [list(nodes)], "xpaths": [list(xpaths)]}

        encoding = self.feature_extractor(html)
        if not encoding["nodes"][0]:
            raise ValueError("no usable text nodes")
        return {"nodes": encoding["nodes"], "xpaths": encoding["xpaths"]}

    @torch.inference_mode()
    def predict(self, html: str) -> dict:
        parsed = self._extract_page(html)
        inputs = self.processor(
            nodes=parsed["nodes"], xpaths=parsed["xpaths"], truncation=True,
            padding="max_length", max_length=self.max_tokens, return_tensors="pt",
        ).to(self.device)
        with self._lock:
            logits = self.model(**inputs).logits
        if not torch.isfinite(logits).all().item():
            raise RuntimeError("model produced NaN/Inf logits")
        probs = torch.softmax(logits.cpu().double() / self.temperature, dim=-1)[0]
        score = probs[self.phishing_id].item()
        return {
            "verdict": self.id2label[self.phishing_id if score >= self.threshold
                                     else self.benign_id],
            "phishing_score": round(score, 4),
            "benign_score": round(probs[self.benign_id].item(), 4),
            "threshold": self.threshold,
            "input_tokens": int(inputs["attention_mask"].sum().item()),
        }


class LayaClassifier:
    """A Laya (ModernBERT) checkpoint fine-tuned to answer one yes/no question.

    It reads cleaned markup as plain text. The calibrated temperature ships in
    rl_agent_config.json and laya applies it itself, so the score comes back
    ready to use and must not be scaled again.
    """

    def __init__(self, model_dir: Path):
        model_dir = Path(model_dir).resolve()
        if not (model_dir / "model.safetensors").is_file():
            raise ModelUnavailable(f"no saved model at {model_dir}")
        self.model_dir = model_dir

        metadata = _load_metadata(model_dir)
        self._preprocessing = metadata.get("preprocessing")
        if not self._preprocessing or "strip_tags" not in self._preprocessing:
            raise ModelUnavailable("artifact has no recognised preprocessing metadata")
        question = metadata.get("question") or {}
        if question.get("t") != "noul" or not question.get("ins"):
            raise ModelUnavailable(f"expected a noul question in metadata; got {question}")
        # Same wording the head was fine-tuned on; any other phrasing changes the score.
        self._questions = {"phishing": {"type": "noul", "instructions": question["ins"]}}

        threshold = float(metadata.get("inference", {}).get("operating_threshold", 0.5))
        if not math.isfinite(threshold) or not 0 <= threshold <= 1:
            raise ModelUnavailable("invalid threshold in saved metadata")
        self.threshold = threshold
        self.test_metrics = metadata.get("test_metrics", {})

        # transformers wraps ModernBERT in torch.compile at import time, which torch
        # refuses on Python 3.14. Compiling only changes speed, never scores.
        if sys.version_info >= (3, 14):
            def _passthrough_compile(model=None, **kwargs):
                return (lambda fn: fn) if model is None else model
            torch.compile = _passthrough_compile
        try:
            from laya import Agent
        except ImportError as exc:
            raise ModelUnavailable(f"laya is not installed: {exc}") from None
        # CPU only, as with MarkupLM: a public endpoint should not wait on an accelerator.
        self.agent = Agent(str(model_dir), device="cpu")

        self._lock = threading.Lock()

    def predict(self, html: str) -> dict:
        cleaned = _clean_markup(html, self._preprocessing)
        if not cleaned.strip():
            raise ValueError("no usable markup")
        with self._lock:
            result = self.agent.predict(cleaned, self._questions)
        score = float(result["answers"]["phishing"]["noul"])
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise RuntimeError(f"model produced an invalid score: {score}")
        return {
            "verdict": "phishing" if score >= self.threshold else "benign",
            "phishing_score": round(score, 4),
            "benign_score": round(1 - score, 4),
            "threshold": self.threshold,
            "input_tokens": int(result.get("usage", {}).get("input_tokens", 0)),
        }
