from __future__ import annotations

import json
import re
from typing import Any

from google import genai
from google.genai import types

from .config import settings
from .models import HeuristicResult, LlmResult

SYSTEM_PROMPT = """You are LinkGuard, a security assistant for a URL-only proof of concept.
You never visit, fetch, or assume the contents of a destination page.
Classify the URL string as phishing, malware, or benign using only the URL and the
heuristic signals provided.

Rules:
- Do not invent WHOIS, certificate, page content, brand impersonation evidence, or
  threat-feed matches that were not supplied.
- "benign" means the URL string does not look malicious — never claim it is safe.
- Prefer phishing when the URL impersonates login, verification, billing, or a brand
  on an unrelated host.
- Prefer malware when the path looks like a payload (exe, apk, js dropper, invoice.doc).
- Search, login, and homepage URLs on well-known sites (google.com, youtube.com, wikipedia.org, github.com, microsoft.com, apple.com) are benign even if the query string is long.
- reasoning must be 2-4 short sentences a non-expert can learn from.

Return JSON only:
{"label":"phishing"|"malware"|"benign","confidence":0-100,"reasoning":"..."}
"""


class LlmError(RuntimeError):
    pass


def _extract_json(text: str) -> dict[str, Any]:
    text = text.strip()
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            return payload
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise LlmError("Gemini did not return JSON")
    payload = json.loads(match.group(0))
    if not isinstance(payload, dict):
        raise LlmError("Gemini JSON was not an object")
    return payload


async def classify(normalized_url: str, heuristic: HeuristicResult) -> LlmResult:
    if not settings.gemini_api_key:
        raise LlmError("GEMINI_API_KEY is not configured")

    user_payload = {
        "url": normalized_url,
        "heuristic": heuristic.model_dump(),
        "instruction": "Classify this URL from its string and heuristic signals only.",
    }

    try:
        client = genai.Client(api_key=settings.gemini_api_key)
        response = await client.aio.models.generate_content(
            model=settings.gemini_model,
            contents=json.dumps(user_payload, ensure_ascii=True),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.2,
                response_mime_type="application/json",
            ),
        )
    except Exception as exc:  # noqa: BLE001 - SDK raises several types
        raise LlmError(f"Gemini request failed: {exc}") from exc

    text = (response.text or "").strip()
    if not text:
        raise LlmError("Gemini returned an empty response")

    try:
        payload = _extract_json(text)
    except (json.JSONDecodeError, LlmError) as exc:
        raise LlmError("Gemini returned invalid JSON") from exc

    label = str(payload.get("label", "")).lower().strip()
    if label not in {"phishing", "malware", "benign"}:
        raise LlmError(f"Gemini returned an invalid label: {label}")

    try:
        confidence = int(payload.get("confidence", 0))
    except (TypeError, ValueError) as exc:
        raise LlmError("Gemini returned an invalid confidence") from exc
    confidence = max(0, min(100, confidence))

    reasoning = str(payload.get("reasoning") or "").strip()
    if not reasoning:
        raise LlmError("Gemini returned no reasoning")

    return LlmResult(
        label=label,  # type: ignore[arg-type]
        confidence=confidence,
        reasoning=reasoning,
        status="ok",
    )
