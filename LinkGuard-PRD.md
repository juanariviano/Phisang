# LinkGuard — Product Requirements Document

**Version:** v0.1 (3-day POC scope)
**Status:** Draft for team review
**Owner:** Novellina
**Last updated:** 2026-08-18

---

## 1. Overview

LinkGuard is a malicious URL detection tool inspired by uBlock-style content blocking. A user submits or navigates to a URL; LinkGuard checks it against a known-threat database and returns a clear verdict — **without ever fetching or rendering the destination page**.

This document defines the **v0.1 proof of concept**: a threat-intelligence lookup against the [URLhaus](https://urlhaus.abuse.ch/) database, exposed through a web scanner and a browser-extension prototype. It deliberately excludes machine-learning scoring, which is scoped as a v1 follow-on (see [Section 10](#10-out-of-scope--future-roadmap)).

The goal of v0.1 is a credible, honestly-communicated demo that can be built and rehearsed in **3 working days**, ending in a short submission video.

---

## 2. Problem statement

Traditional blocklist-based blockers (uBlock Origin and similar) are fast and locally auditable, but they only catch threats that have already been discovered, verified, and published to a feed. A URL that hasn't been reported yet passes through with no signal at all — and worse, an unlisted URL is often silently treated as "safe" by both users and naive tooling.

LinkGuard v0.1 addresses the second half of that problem first: it makes the **absence** of a match an honest, visible state ("not listed" — not "safe"), and builds the plumbing (normalization, lookup adapter, risk-response schema, extension UI) that a future ML layer can plug into without a redesign.

---

## 3. Goals

- Detect known-malicious URLs with high confidence using a real, current threat-intelligence source (URLhaus).
- Return a response that is honest about what was and wasn't checked — no destination fetching, no fabricated "safe" verdicts.
- Demonstrate the detection flow in two surfaces: a web scanner and a browser-extension warning interstitial.
- Ship a working, repeatable demo and a short video within 3 days.

### Non-goals (v0.1)

- Any machine-learning / lexical-heuristic scoring of unlisted URLs.
- Crawling, rendering, or otherwise visiting the destination page.
- A published, store-reviewed browser extension (a local/dev-mode prototype is sufficient).
- Controlled "suspicious" demo websites (deferred — see roadmap).
- Multi-source threat-intel aggregation (URLhaus only for v0.1).

---

## 4. Target users & context

| User | Need |
|---|---|
| Hackathon / submission judges | Understand the concept in under 3 minutes; see it work live or on video |
| Team members (3-person build team) | A clear, buildable spec that fits a 3-day window |
| End user (persona, shown in demo) | Wants to know *before* clicking whether a link is known-dangerous |

---

## 5. Scope (v0.1)

### In scope

- URL submission via a simple web scanner (`POST /api/v1/check`).
- URL parsing/normalization (scheme, host casing, trailing slash, IDN — no network resolution).
- Exact-match and host/registered-domain lookup against a local URLhaus snapshot.
- Four UI states: checking, matched (dangerous), not listed (unknown), feed unavailable (degraded).
- Browser-extension prototype: toolbar status icon, popup detail panel, full-page blocked interstitial.
- A pinned demo snapshot and 3–4 rehearsed demo URLs.

### Out of scope

See [Section 10](#10-out-of-scope--future-roadmap).

---

## 6. Functional requirements

### 6.1 URL intake & normalization

- Accept only `http` and `https` schemes; reject anything else with `unsupported_scheme`.
- Reject oversized input (e.g. > 2048 characters) with `input_too_large`.
- Normalize: lowercase scheme/host, strip default ports, collapse redundant slashes, decode-then-re-encode percent sequences consistently, resolve IDN to punycode for comparison.
- Never resolve DNS or make an outbound request to the submitted URL.

### 6.2 Threat-intelligence lookup

- Source: [URLhaus](https://urlhaus.abuse.ch/) database.
- Auth: LinkGuard registers a free Auth-Key at `auth.abuse.ch` (required as of URLhaus's current API policy).
- Ingestion: pull the full CSV/JSON export on a schedule (feed refreshes server-side every ~5 minutes; LinkGuard does not need to poll that often — every 15–30 minutes is enough for a POC) and load it into a local SQLite table, indexed on:
  - exact normalized URL
  - hostname / registered domain
- Match precedence: exact full-URL match → hostname/registered-domain match → no match.
- "No match" is returned as `not_listed`, never as `safe`.
- If the local snapshot fails to load or is older than a configured staleness threshold, return `threat_intel_unavailable` — the response must be marked **degraded**, not clean.

### 6.3 Risk response

Every request returns one of four classifications:

| Classification | Trigger | UI treatment |
|---|---|---|
| `dangerous` | Exact URL or domain match in URLhaus | Full-page blocked interstitial, red |
| `not_listed` | No match found | Neutral "not listed" badge, slate — explicit unknown-is-not-safe caveat |
| `checking` | Request in flight | Transient spinner state (client-side only) |
| `unavailable` | Feed failed to load / stale beyond threshold | Degraded banner, violet — never silently downgrades to `not_listed` |

Example response body:

```json
{
  "scan_id": "scan_7bd44a10",
  "normalized_url": "http://185.220.101.47/wp-content/uploads/invoice_8837.exe",
  "classification": "dangerous",
  "threat_intel": {
    "matched": true,
    "source": "URLhaus",
    "threat_type": "malware_download",
    "first_seen": "2026-08-16T14:22:00Z",
    "feed_snapshot": "2026-08-18T06:00:00Z"
  },
  "signals": [
    "Exact URL match against the URLhaus snapshot (id 3341829)",
    "Host is a bare IP literal with no associated domain name"
  ],
  "limitations": [
    "The destination was not visited or analyzed",
    "This result reflects a database lookup only — no ML scoring is applied in v0.1"
  ]
}
```

### 6.4 Web scanner (frontend)

- Single input field, submit button, and a result panel driven entirely by the API response schema above.
- All four classification states must be visually distinct without relying on color alone (icon + label + color, per accessibility requirement).
- Display feed snapshot timestamp and policy version on every result for reproducibility.

### 6.5 Browser extension prototype

- Toolbar icon reflects current-tab status via a colored dot (checking / dangerous / not-listed / unavailable).
- Click-to-open popup shows: classification, match source, signals, a collapsible technical-details panel (`scan_id`, `normalized_url`, `feed_snapshot`, `policy_version`), and an explicit "not listed ≠ safe" caveat when relevant.
- On a `dangerous` result, replace the page view with a full blocked interstitial: classification, threat feed, threat type, first-seen date, signal list, **"Go back" as the primary action**, and a visually de-emphasized "continue anyway" link (demo/testing only — disabled or logged, never a silent bypass).
- On `unavailable`, show a non-blocking banner ("threat feed unreachable — this is a degraded result, not a clean one") rather than blocking navigation.
- A working interactive HTML prototype of this flow already exists (`linkguard-extension-ui.html`) and should be treated as the UI reference/spec for implementation, not just a mockup.

---

## 7. Non-functional requirements

- **Privacy:** never send full submitted URLs to any third party beyond the URLhaus lookup itself; redact query strings/credentials from logs.
- **Reliability for demo:** the feed snapshot used in the live/recorded demo must be frozen before rehearsal so results don't shift mid-presentation.
- **Latency:** local lookup should resolve in well under 200ms since it's an indexed local query, not a live remote call per request.
- **Failure honesty:** any internal failure (parser, DB, feed load) must surface as `unavailable`/`unknown`, never silently resolve to a reassuring result.
- **Licensing:** LinkGuard must follow abuse.ch's usage terms for URLhaus data (attribution, non-resale/community-use conditions) — note this in the methodology/README.

---

## 8. System architecture (v0.1)

```
Web scanner ─┐
             ├─▶ Analysis API ─▶ URL validation/normalization ─▶ URLhaus lookup adapter ─▶ Risk response
Extension ───┘                                                         │
                                                                  Local snapshot (SQLite)
                                                                  refreshed from URLhaus export
```

No feature-extraction, model-inference, or risk-fusion components exist in v0.1 — the "risk response" step in v1+ is where ML fusion will be inserted later without changing the response schema.

---

## 9. Team split & 3-day plan

| Day | Focus | Owner(s) |
|---|---|---|
| Day 1 | Register URLhaus Auth-Key; pull CSV/JSON export; build normalization + lookup index; `POST /api/v1/check` endpoint | Backend/data |
| Day 2 | Web scanner UI wired to live API; extension popup + blocked interstitial + degraded banner; pick/freeze 3–4 demo URLs (real current URLhaus entries + benign controls) | Frontend + Extension |
| Day 3 | End-to-end rehearsal on the frozen snapshot; error/edge-case pass; record and edit the ~2–3 minute demo video; write README/submission notes | Whole team |

Suggested 3-person split: one owns the backend/lookup adapter, one owns the web scanner + extension UI, one owns integration, demo-URL curation, and the video/submission packaging — with all three reviewing the API contract and demo script together on Day 1.

---

## 10. Out of scope / future roadmap

Deferred to v1 and beyond, in rough priority order:

1. **ML-based lexical scoring** for URLs not present in URLhaus (logistic regression / random forest baseline, per the original LinkGuard research brief).
2. **Hybrid risk fusion** combining threat-intel match + model probability into a single explainable score with tuned thresholds.
3. **Controlled demo websites** (benign / suspicious / mock-credential pages) for a fuller live-navigation demo.
4. **Published, store-reviewed browser extension** with permissions review, auth, and abuse prevention.
5. **Additional threat-intel sources** beyond URLhaus, with cross-source dedup.
6. Longer-term research directions (sandboxed crawler, multimodal detection, campaign graph, GraphRAG investigation assistant) as outlined in the original LinkGuard architecture brief.

---

## 11. Success metrics / Definition of done

- [ ] Scanner accepts and validates HTTP/HTTPS URLs only.
- [ ] No submitted destination is ever fetched by LinkGuard.
- [ ] All four classification states render correctly in both the scanner and the extension.
- [ ] "Not listed" is never presented as "safe" anywhere in the UI or API response.
- [ ] Feed/lookup failures surface as `unavailable`, never as a false clean result.
- [ ] Demo runs end-to-end on a frozen snapshot without live network dependency.
- [ ] Demo video (2–3 min) recorded and ready for submission.

---

## 12. Key risks

| Risk | Mitigation |
|---|---|
| URLhaus Auth-Key registration delay | Register on Day 1 morning; it's typically instant, but budget a buffer |
| Demo malicious URL no longer in feed by presentation time | Pull fixture URLs directly from the frozen snapshot, not from memory/old reports |
| Live network dependency fails during demo | Use the local snapshot as primary source; have a recorded video as fallback |
| "Not listed" misread by judges as "safe" | Reinforce the caveat visually (icon + label + copy) in every relevant UI state |
