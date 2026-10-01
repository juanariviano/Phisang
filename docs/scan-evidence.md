# Registration, previews and Explain

Install `backend/requirements.txt`, apply the SQL migration, rebuild the frontend,
then restart the API process:

```powershell
.\backend\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\backend\.venv\Scripts\python.exe backend/scripts/migrate.py
cd web
npm.cmd run build
```

`migrate.py` applies every migration in `backend/migrations`, including this
one; `migrate_scan_evidence.py` applies this one alone.

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
Completed answers are stored in SQL against the original evidence scan ID and
shared by all users scanning the same normalized URL. Repeat results include the
saved explanation and display it without another provider call. Rescan creates
a new observation with no explanation; clicking Explain generates and stores a
fresh answer. Failed or partial explanations are retryable and are never saved.

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
page checks leave purpose/navigation unverified. Provider, model, and prompt
changes apply to newly generated answers; existing answers remain available,
even without provider credentials, until the user rescans.

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
explanations use `ExplanationJson` and `ExplanationKey` (a generation fingerprint
retained for provenance, not a reuse condition). A bounded in-memory cache
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
  `page.preview_available`. Analyze and individual scan responses also include
  `explanation` when already saved, otherwise `null`. Reading a scan never starts
  an LLM request. Image bytes are omitted from JSON responses.

Incomplete scans remain in the audit log but cannot be reused. This includes DNS,
browser, non-2xx page responses and threat-feed failures. A normal subsequent Peel
tries again. Successful history reads still create no additional database row.

When a configured SQL history lookup fails, a normal Peel stops before contacting
scan providers. JSON requests return HTTP 503 with `history_unavailable`; streaming
requests emit an `error` event with the same code. A database outage is not treated
as an address that has never been scanned. Explicit Rescan and Continue requests
can still run fresh checks, with best-effort logging. Once SQL recovers, ordinary
requests reuse saved results again. Installations with history disabled remain
stateless. `/api/v1/health` reports `degraded` when database history is enabled but
unavailable; check SQL connectivity and the configured `DB_HOST`/`DB_PORT` before
investigating the reuse policy.

## File URL restrictions

Known file links (executables, archives, documents, media and data files) are
rejected before the scan archive or threat providers are consulted. The website,
extension and backend share `backend/app/file_types.json`. Webpage suffixes such
as `.html`, `.php` and `.aspx` remain allowed. Checks use the decoded final path
segment, ignoring the query and fragment; a hostname ending in `.com` or `.zip`
is not a file extension.

When fetching a page, the backend checks each preflight redirect URL using HEAD,
then the actual browser navigation URL and response. Attachments and documents
without an HTML/XHTML content type are refused before model inference. Servers
that reject HEAD can still reach the browser check. This is a webpage-content
filter, not file malware scanning. File errors use `unsupported_content` (HTTP
400 or an SSE error) and create no reusable scan result. The extension keeps
navigation paused with an explanation and a Go back button; a file URL cannot
inherit a cached hostname verdict. Existing reuse/early-exit rules still apply
to extensionless URLs: their new destination/content type can only be discovered
when a fresh page fetch occurs.

After changing the extension rules, run `node extension/scripts/sync-web-assets.mjs`
and reload the extension. Build and deploy the website and restart the backend
to apply the server changes. For the isolated browser check:

```powershell
cd web
npm.cmd run build -- --outDir ../backend/data/file-guard-web-build
cd ..
.\backend\.venv\Scripts\python.exe backend/tests/ui_file_guard_smoke.py
```

## Verification

Backend tests use mocked providers and disable live SQL writes. The browser smoke
test serves the production bundle and API fixtures through Playwright routing;
it does not scan websites or contact an LLM:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend/tests -q
.\backend\.venv\Scripts\python.exe backend/tests/ui_evidence_smoke.py
```
