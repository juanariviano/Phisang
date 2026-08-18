# LinkGuard POC

Chrome extension + web scanner + API that classifies URLs as **malware**, **phishing**, or **benign**. This is a 3-day proof of concept: no model training, and the destination page is never fetched.

Detection follows the product flowchart, minus HTML crawling:

1. Normalize the URL (no DNS, no visit).
2. Look it up in [URLhaus](https://urlhaus.abuse.ch/) (exact URL, then host). A match blocks immediately as malware.
3. Run a **placeholder lexical “ML”** (heuristics, not a trained model).
4. If the URL does not look benign, or benign confidence is **≤ 80%**, send the URL string to **Gemini** for classification and educational reasoning.
5. Show a block interstitial or allow navigation with an explicit **not listed ≠ safe** caveat.

```
Web scanner ─┐
             ├─▶ FastAPI ─▶ normalize ─▶ URLhaus ─▶ heuristic ─▶ Gemini (if needed)
Extension ───┘
```

## Requirements

- Python 3.10+ (3.14 is fine)
- Google Chrome
- `URLHAUS_AUTH_KEY` from [auth.abuse.ch](https://auth.abuse.ch/)
- `GEMINI_API_KEY` from [Google AI Studio](https://aistudio.google.com/apikey) (needed for phishing / low-confidence paths)

## Setup

```bash
cp .env.example .env
# fill URLHAUS_AUTH_KEY and GEMINI_API_KEY

cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Scanner: [http://localhost:8000](http://localhost:8000)

### Load the extension

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. **Load unpacked** → select the `extension/` folder
4. Keep the API running on port 8000
5. Leave **Protect navigations** on in the toolbar popup while demoing; turn it off when you need to browse normally

The extension intercepts `http(s)` navigations (except the scanner itself), shows a checking page, then either continues or replaces the tab with a blocked interstitial.

## Demo URLs

Use these in the **scanner**. Do **not** open the malware sample in a normal tab without the extension; the point of LinkGuard is to stop that navigation.

| Case | URL | Expected path |
|---|---|---|
| Benign, high confidence | `https://www.wikipedia.org` | URLhaus miss → heuristic allow (caveat shown) |
| Known malware | `http://77.73.133.113/lego/mine.exe` | URLhaus match → `malware`, no Gemini |
| Phishing-looking, unlisted | `https://secure-login-paypal-verify.account-update.xyz/signin?session=unlock` | Heuristic escalate → Gemini `phishing` + reasoning |
| Degraded | Omit `GEMINI_API_KEY` and retry the phishing URL | `unavailable` — not treated as benign |

## API

`POST /api/v1/analyze`

```json
{ "url": "https://www.wikipedia.org", "client": "web" }
```

Also: `GET /api/v1/health`, `GET /api/v1/meta`, `GET /api/v1/scans`.

Classifications: `malware` | `phishing` | `benign` | `unavailable`.  
Decision stages: `urlhaus` | `heuristic` | `llm` | `error`.

## Privacy and licensing

- Keys live in `.env` only. Never put URLhaus or Gemini credentials in the extension.
- Query strings and credentials are stripped from backend logs.
- URLhaus data is provided by [abuse.ch](https://urlhaus.abuse.ch/). Follow their terms (attribution, non-resale / community use).
- This prototype is load-unpacked only. It is not store-ready and is not production protection.

## Project layout

```
backend/app/     FastAPI, URLhaus adapter, heuristics, Gemini, policy
web/             Scanner UI (served by the API)
extension/       Chrome Manifest V3 (checking, blocked, popup, banner)
```
