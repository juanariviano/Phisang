# Scan evidence and explanations

Approved design: enrich each fresh scan with RDAP registration facts; capture a
bounded JPEG in the existing guarded browser; provide an on-demand explanation
through an OpenAI-compatible chat completion endpoint. The user explicitly
approved sending the screenshot with the findings when Explain is clicked.

Registration is supplementary information, not proof of safety or danger. Use
the IANA RDAP bootstrap and the public suffix list to select the registered
domain. Missing/redacted records must not change the verdict. Bound lookup time.

Keep JPEG bytes in SQL Server VARBINARY(MAX), with scan findings in the existing
JSON record. Serve previews through a local image endpoint. Replayed scans refer
to their original evidence. If SQL is unavailable, keep bounded process-local
evidence so the current result still works. Do not expose image bytes in listings.

Explain accepts a scan ID, uses server-owned findings and an optional JPEG,
and returns validated plain-text summary, reasons, and advice. The provider URL,
key and model are configurable; defaults target Gemini 3.5 Flash Lite through
Google's OpenAI-compatible endpoint. No LLM call occurs during a scan. Treat page
text and screenshots as untrusted evidence, never instructions. Cache successful
explanations per scan and provider configuration; failures remain retryable.

Incomplete/error scans remain audit records but cannot satisfy a history lookup.
The next ordinary Peel performs a fresh scan. Reusing a successful scan still
does not create another database log entry. Existing Rescan behavior stays.

Keep the banana identity and current layout. Lead with an understandable verdict,
practical advice, optional captured preview and Explain. Put registration facts
and technical evidence in expandable sections. Remove false privacy claims,
hardcoded model-quality claims, percentage certainty and live malware examples.

Validation: mocked RDAP/provider/SQL tests; retry and cache regression tests;
preview MIME/size checks; production frontend build; desktop/mobile browser
checks with mocked API responses. No paid provider request in automated tests.

Implementation order: models/config; registration and evidence storage; guarded
preview capture; history eligibility and orchestration; explanation API; UI;
migration/config notes and verification.

## Requested follow-up: streaming and scan layout

The user requested real streaming explanations, completed results under the form,
a transition from the initial columns to rows, and an animated scanning banana.
Use provider SSE with parsed partial JSON snapshots, retain final structured
validation and SQL caching, and show interrupted responses as incomplete. Use
the existing Framer Motion dependency for layout transitions and SVG/CSS for
banana movement. Keep the stacked layout on subsequent scans and honor reduced
motion. Verify early text arrival, failures, shared requests, UTF-8 frame splits,
initial/completed layout positions and reduced-motion behavior.
