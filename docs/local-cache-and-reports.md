# Local cache, false-positive reports and the HTTP penalty

Apply the SQL migrations and reload the unpacked extension:

```powershell
.\backend\.venv\Scripts\python.exe backend/scripts/migrate.py
```

`backend/scripts/migrate.py` applies every file in `backend/migrations` in
filename order. Each one is additive and safe to run again, so it can be re-run
after a pull. `migrate_scan_evidence.py` still applies `001` on its own.

## The extension's local cache

An exact hostname this browser already checked is answered from
`chrome.storage.local` instead of the API, so ordinary repeat browsing costs no
scan request: no round trip to wait for, and no SQL read on the server.

The checking screen still holds the tab, exactly as before — what changes is
that it resolves from storage rather than from a scan. Navigation interception
is unchanged, so **Continue anyway** still releases one visit only. Paths, queries,
fragments, schemes and ports share a hostname entry: `test.com/home`,
`test.com/login` and `test.com/inventory` reuse one result. `dev.test.com` and
`www.test.com` each require their own check. The API's SQL lookup remains per URL.

What may be kept (`extension/cache.js`):

- Completed `benign`, `phishing` and `malware` results, including caution verdicts.
- No error code, failed page check, error decision stage or unknown verdict.
- High-risk cached results still block navigation using the shared verdict rules.

Entries expire after six hours, at most 200 are held (oldest dropped first), and
the rules are applied again on the way out, so an entry written by an older
version of the extension cannot release an address today. A rescan always asks
the server and replaces the hostname entry; a failed scan invalidates it.
A result served from the cache does not renew its own
lifetime, so an address scanned once is still re-checked within the day.

A cached result identifies the previously scanned URL; previews and explanations
retain that scan's evidence ID. It does not claim that every path was inspected.
The popup reports how many hostnames are held and **Clear local cache** empties it;
the next visit to each is scanned again. The cache is per browser profile and is
never uploaded. The old per-URL cache is not reused after this update, so the first
visit to each hostname establishes a new entry.

## False-positive reports

`POST /api/v1/scans/{scan_id}/report` with an optional
`{"client": "web" | "extension", "reason": "..."}` body appends a row to
`dbo.FalsePositiveReports` and answers
`{"status": "recorded", "report_id": …, "scan_id": …}`. 404 means the scan is
unknown, 503 that the scan database is unconfigured or unreachable, and 422 that
the reason is longer than 1000 characters.

Reports are stored for review by hand. Filing one never changes the scan's
verdict, the site's counters or what a later scan decides — a client that could
talk its own result down would be a way to get a phishing page waved through.
The row keeps the verdict, classification and risk score as they stood when the
report was filed, so a later rescan cannot rewrite what the reporter was
disagreeing with, and it is filed against the durable evidence scan ID.

The button appears on the website and in the extension wherever a result is
displayed as high risk or "Be cautious".

## Plain HTTP raises the risk score

A plain-HTTP address can be read and rewritten in transit, so `app.risk` adds
`HTTP_RISK_PENALTY` (0.1, or 10 points) to the final risk score. The sum is
capped at 1.0, so a score can never exceed 100%; a URLhaus match already at 1.0
stays there and says so in its signals.

The penalty is applied once, in `policy._base`, so every decision stage gets it
— including page analysis, whose model score previously carried no sign of the
scheme at all. The lexical gate in `heuristics.py` no longer scores the scheme
itself, so an address is not charged twice for it. A result replayed from the
scan archive is left alone: its stored score already carries the penalty.

Because the penalty moves the final score, it can move the risk band with it: an
http page scoring 0.55 now reads as `MALICIOUS` rather than `POTENTIALLY
UNSAFE`, and the extension stops anything from 0.6 up. Verdict counters in SQL
are unaffected — they are banded from the page model's own score.
