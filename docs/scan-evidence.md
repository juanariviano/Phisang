# Registration, previews and Explain

Install `backend/requirements.txt`, apply the SQL migration, rebuild the frontend,
then restart the API process:

```powershell
.\backend\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\backend\.venv\Scripts\python.exe backend/scripts/migrate_scan_evidence.py
cd web
npm.cmd run build
```

The migration adds three nullable columns to `dbo.Scans` and can be run again.
It preserves existing rows. A new scan is needed to capture an image for an old
record. Missing preview columns do not prevent verdict logging; preview storage
and explanation persistence will warn until the migration is applied.

## Provider configuration

Set these in the repository root `.env`:

```dotenv
EXPLANATION_API_KEY=your-key
EXPLANATION_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
EXPLANATION_MODEL=gemini-3.5-flash-lite
EXPLANATION_INCLUDE_SCREENSHOT=true
```

An existing `GEMINI_API_KEY` is accepted only when using Google's hostname.
The [Google compatibility API](https://ai.google.dev/gemini-api/docs/openai)
accepts chat completions and image data URLs. The default
[Gemini 3.5 Flash Lite model](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite)
supports image input. To change providers, set all three provider values; use a
model that supports image input and JSON-object response mode. Set
`EXPLANATION_INCLUDE_SCREENSHOT=false` for text-only models.

No provider call occurs during scanning. Explain sends the URL, scan evidence,
registration facts and available JPEG to the configured provider only on demand.
It does not send the full HTML. Treat scans of URLs containing private query
parameters accordingly. Provider output is validated and rendered as text.
Successful answers are cached against the evidence, provider and model. Failures
are retryable. Changing evidence or model invalidates the cached answer.

The website requests `Accept: text/event-stream` on Explain. The API streams
`snapshot` events as the provider generates text, then a validated `done` event.
An `error` event leaves the answer marked incomplete and retryable; partial
answers are never saved. Concurrent readers share one provider request, and
cached explanations arrive immediately. Clients that omit this Accept header
still receive the complete JSON response. Reverse proxies should disable response
buffering for this endpoint; the API sends `X-Accel-Buffering: no` and heartbeat
comments. The provider request uses `stream: true` through the same compatible
chat-completions endpoint.

Explanations start with the destination's apparent purpose, using the captured
title and preview. They describe changes from the submitted address to the final
address, including changes of hostname. This is observed navigation, not a
complete redirect chain; intermediate hops are not stored. Skipped or failed
page checks leave purpose/navigation unverified. Prompt changes invalidate saved
explanations so the next Explain request uses the updated guidance.

After the first completed scan, the website transitions from its initial desktop
columns to a single column with the result below the URL form. Rescans keep that
layout. The scanning banana sways above a moving shadow; reduced-motion settings
disable that animation and the layout movement.

## Registration and screenshots

RDAP is the structured successor to WHOIS for generic top-level domains
([ICANN](https://www.icann.org/rdap/)). The lookup uses the public suffix list to
find the registered domain and IANA's RDAP bootstrap to find its registry.
Requests and redirects are restricted to public HTTPS destinations, with an
eight-second total budget. An unavailable or private record does not alter risk.
`RDAP_ENABLED=false` disables lookup.

The existing Chromium fetch captures one viewport JPEG, up to 600 KB. Images and
fonts are allowed through the existing URL guard; media remains blocked. No page
is fetched solely to produce a preview, so URLhaus/known-domain early decisions
may have none. `PAGE_PREVIEW_ENABLED=false` disables capture.

JPEGs are stored as `VARBINARY(MAX)` in `dbo.Scans.ScreenshotJpeg`. Base64 is used
only in the provider request. Registration facts remain in `RawResponseJson`;
explanations use `ExplanationJson` and `ExplanationKey`. A bounded in-memory cache
keeps the current preview/explanation available if SQL is temporarily offline;
that fallback is lost on restart. A replay uses the original evidence scan ID.

## API additions

- `POST /api/v1/analyze` accepts `Accept: text/event-stream` for live `progress`
  events (`stage`, `label`, `detail`, `status`), followed by a `done` scan response
  or an `error` event. Without this header, its existing JSON behavior is unchanged.
  Domain lookup may run alongside threat/page checks. The UI shows only stages
  actually reached, elapsed time, and an indeterminate bar rather than a guessed
  completion percentage. The displayed result's risk percentage is separate.

- `GET /api/v1/scans/{scan_id}/preview`: JPEG, or 404 when unavailable.
- `POST /api/v1/scans/{scan_id}/explain`: `{summary, reasons, advice, model,
  generated_at, included_screenshot}`. No request body; evidence comes from the
  server. Returns 404 for missing scans, 503 for missing configuration, 429 when
  busy, or 502 if the provider fails or returns malformed output.
- Scan responses include `domain_info`, `scanned_at`, `evidence_scan_id`, and
  `page.preview_available`. Image bytes are omitted from JSON responses.

Incomplete scans remain in the audit log but cannot be reused. This includes DNS,
browser, non-2xx page responses and threat-feed failures. A normal subsequent Peel
tries again. Successful history reads still create no additional database row.

## Verification

Backend tests use mocked providers and disable live SQL writes. The browser smoke
test serves the production bundle and API fixtures through Playwright routing;
it does not scan websites or contact an LLM:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend/tests -q
.\backend\.venv\Scripts\python.exe backend/tests/ui_evidence_smoke.py
```
