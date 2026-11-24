# ScamRead scam checker

The free scam checker behind **[app.scamread.com](https://app.scamread.com)**.
Paste a suspicious SMS, WhatsApp message, email or link and it explains the
warning signs in plain words: pressure and threats, OTP or password requests,
payment demands, fake brand links, risky domain endings and known scam
campaigns.

It is fast (a check takes a few milliseconds on the server) and fully
rule-based: no AI model sees the message and nothing is sent to third parties.

## Privacy: what is and isn't stored

**Never stored:** the message itself, a hash of it, phone numbers, email
addresses, IP addresses, or anything about the person who ran the check.
Messages are checked in memory. A repeated message may be answered from a
short-lived memory cache (15 minutes, keyed by a SHA-256 hash, cleared on
restart, never written to disk).

**Stored, only for medium and high-risk results:** the *shape* of the scam, so
we can track campaigns over time:

| Saved | Example |
|---|---|
| Brand it pretended to be | `sbi` |
| Whether the link didn't match the brand | `true` |
| Domain endings of the links | `.tk` |
| The scam link's domain (not the full link) | `sbi-kyc.tk` |
| Scam types | `banking_phishing` |
| Warning-sign IDs | `urgency`, `kyc`, `brand_mismatch` |
| Pressure score (0–100) | `65` |
| First seen, last seen, count | `2026-11-24`, `2026-11-25`, `14` |

## How it works

```
message ──► extract links, domains, numbers ──► score with rules ──► match known campaigns ──► result
                                                   ▲                        ▲
                                     patterns from the database   published campaigns (in memory)
```

- **Patterns** (brands and their real websites, pressure phrases, risky domain
  endings, …) live in a SQLite database. On first start it is filled from
  [`app/seed/patterns.json`](app/seed/patterns.json). Patterns are compiled
  once and refreshed every 5 minutes, so new patterns work without a restart.
- **Scoring** is in [`app/analysis/rule_engine.py`](app/analysis/rule_engine.py).
  The `core` patterns reproduce the original v1 engine exactly (there is a test
  that proves it on thousands of messages); `extended` adds more brands
  (PayPal, Paytm, Amazon, DHL, …) and abused domain endings (`.top`, `.icu`, …).
- **Speed:** compiled patterns, a short memory cache for repeated messages, an
  in-memory index of campaign indicators, and database writes done in the
  background in batches.

## API

`POST /api/analyze` with `{"text": "..."}` (1–20,000 characters):

```json
{
  "indicators": { "urls": [], "domains": ["sbi-kyc.tk"], "phone_numbers": [], "...": [] },
  "total_indicators": 1,
  "analysis": {
    "risk_score": 100,
    "risk_level": "high",
    "red_flags": ["Uses urgent or pressure-based language", "..."],
    "suspected_types": ["credential_phishing", "banking_phishing"],
    "urgency_score": 65,
    "claimed_brand": "sbi",
    "brand_mismatch": true,
    "official_domains": ["sbi.co.in"],
    "link_domains": ["sbi-kyc.tk"]
  },
  "campaign": { "matched": false, "campaign": null, "confidence": 0 }
}
```

The first four `analysis` fields are unchanged from v1; the rest are new.
Also public: `GET /api/health`, `POST /api/intelligence/lookup`,
`GET /api/intelligence/campaigns/{id}` (published campaigns only).

### Admin panel

**app.scamread.com/admin**: log in with the admin username and password.

| Screen | What you can do |
|---|---|
| Dashboard | Checks per day, risky share, most-faked brands, domain endings and scam websites seen |
| Brands | Add a brand and its real websites, or switch one off |
| Warning signs | Add phrases in plain words (made into safe whole-word patterns) and risky domain endings; switch any off |
| Campaigns | Group scam websites, numbers and wallets; publish to warn people by name |
| Account | Change password (logs out other browsers) |

Security: passwords are stored as scrypt hashes; the session cookie is
httpOnly, `Secure`, `SameSite=Strict` and only its SHA-256 is stored; changes
need an `X-ScamRead-Admin` header that other sites can't send; 5 wrong
passwords lock an address out for 15 minutes; the page is `noindex` and
`no-store`.

The first account comes from `SCAMREAD_ADMIN_USER` and
`SCAMREAD_ADMIN_PASSWORD_HASH` in `/etc/scamread.env`. Forgot the password? On
the server:

```bash
cd /opt/scamread && sudo -u scamread venv/bin/python -m app.admin_cli set-password BAYARD
```

### Admin endpoints

The panel uses these. Scripts can also call them with the server's admin token
as `Authorization: Bearer <token>` (switched off if `SCAMREAD_ADMIN_TOKEN` is empty).

| Endpoint | What it does |
|---|---|
| `GET /api/admin/stats` | Top impersonated brands, domain endings, scam domains and scam shapes |
| `GET /api/admin/patterns` | List every pattern |
| `POST /api/admin/patterns/brands` | Add a brand: `{"name": "zomato", "legit_domains": ["zomato.com"]}` |
| `POST /api/admin/patterns/rules` | Add a phrase or regex: `{"category": "urgency", "value": "\\blast chance\\b"}` |
| `POST /api/admin/patterns/tlds` | Add a risky domain ending: `{"tld": ".xyz"}` |
| `POST /api/admin/patterns/active` | Switch a pattern off or on |
| `GET /api/admin/patterns/export` | Download patterns as a pattern pack |
| `POST /api/admin/campaigns` | Create a campaign; add indicators and publish it with the next two |
| `POST /api/admin/campaigns/{id}/indicators` | Attach a domain, number, wallet, … |
| `POST /api/admin/campaigns/{id}/review?review_status=published` | Publish (only published campaigns are matched) |
| `POST /api/intelligence/capture` | Analyst capture of labelled indicators (message text not stored) |

Example:

```bash
curl -s https://app.scamread.com/api/admin/stats -H "Authorization: Bearer $SCAMREAD_ADMIN_TOKEN"
```

## Keeping the scam database private as it grows

The code is open source; the **data doesn't have to be**.

1. **The database is never in git.** `data/` is in `.gitignore`. Everything
   learnt from real checks and everything added through the admin API stays
   on the server.
2. **Private pattern packs.** Put JSON files in the same format as
   `app/seed/patterns.json` into the folder named by
   `SCAMREAD_PRIVATE_PATTERNS_DIR` (on the server:
   `/opt/scamread/data/private-patterns/`). They are loaded at start-up and
   never published. `GET /api/admin/patterns/export?source=analyst` produces
   such a file from patterns added through the API.
3. **Closing the code later.** Make the GitHub repository private
   (Settings → General → Danger zone → Change visibility). Code that was
   already published stays available under the MIT licence to anyone who has
   a copy, but nothing new will be. ScamRead keeps full rights to its own
   code and can continue it under any licence.

## Run it locally

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
SCAMREAD_ENV=development uvicorn app.main:app --reload
# open http://127.0.0.1:8000  (API docs at /docs in development mode)
python -m pytest -q
```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `SCAMREAD_ENV` | `production` | `development` shows `/docs` |
| `SCAMREAD_DATABASE_PATH` | `data/scamread.db` | SQLite file |
| `SCAMREAD_ADMIN_TOKEN` | *(empty: off)* | Token for scripts calling admin endpoints |
| `SCAMREAD_ADMIN_USER` | *(empty)* | First admin panel username |
| `SCAMREAD_ADMIN_PASSWORD_HASH` | *(empty)* | Its password hash (`python -m app.admin_cli hash`) |
| `SCAMREAD_PRIVATE_PATTERNS_DIR` | *(empty)* | Folder of private pattern packs |
| `SCAMREAD_CACHE_TTL_SECONDS` | `900` | Memory cache lifetime |
| `SCAMREAD_RECORD_MIN_RISK_SCORE` | `40` | Lowest score whose shape is recorded |
| `SCAMREAD_PATTERN_RELOAD_SECONDS` | `300` | How often patterns are reloaded |
| `SCAMREAD_ASSET_VERSION` | release date | Bump to refresh browser caches |

## Deploying

[`deploy/`](deploy/) has the systemd service, an nginx snippet (HTTP/2, gzip,
static files cached for a year) and `deploy.sh`, which pulls this repository,
keeps the database, installs dependencies, restarts the service and rolls back
if the health check fails.

## WordPress pop-up

[`wordpress/scamread-checker-promo`](wordpress/scamread-checker-promo) is a
small WordPress plugin that shows a dismissible "Got a suspicious message?"
card on scamread.com linking to the checker. Install
`wordpress/dist/scamread-checker-promo.zip` (Plugins → Add New → Upload) and
adjust it under Settings → ScamRead Checker.

## Licence

Code: [MIT](LICENSE). Fonts in `static/fonts/` (Inter, JetBrains Mono): SIL
Open Font License 1.1. The ScamRead name and logo are not covered by the code
licence.

ScamRead is an independent AI cybersecurity research company. It is not a
government site or a law firm, and nothing here is legal advice.
