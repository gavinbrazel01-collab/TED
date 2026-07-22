# TED tender watch — OSINT / link-analysis / digital-forensics niche

Daily automated check of TED (Tenders Electronic Daily, the EU's official
procurement notice portal) for tenders relevant to siren.io's niche: OSINT,
link analysis, criminal/investigative intelligence platforms, digital
forensics, and data-fusion systems for police / public-safety buyers —
including "supplies" (software licensing) notices, not just services/dev
notices.

## How it works

1. `fetch_tenders.py` runs daily via GitHub Actions (`.github/workflows/daily-ted-check.yml`,
   05:00 UTC). It queries the free, public TED Search API by CPV code and by
   multilingual keyword, merges the results, and compares against
   `data/seen.json` (a running list of notice IDs already reported) so only
   genuinely new notices show up.
2. It writes `data/latest.json` (today's new candidates) and commits both
   data files back to this repo.
3. A separate Cowork scheduled task (set up in your Claude conversation, not
   part of this repo) reads `data/latest.json` every morning, uses Claude's
   judgment to decide which candidates are actually relevant to your niche
   (not just keyword noise), and drops a draft email in your Gmail with the
   shortlist and tender IDs.

## One-time setup (you)

1. Create a new **public** GitHub repository (public is required — the
   downstream email step reads `data/latest.json` over a plain
   `raw.githubusercontent.com` URL, which only works unauthenticated for
   public repos. The file only ever contains public procurement data:
   notice IDs, titles, buyer names — nothing sensitive).
2. Upload these three items into the repo, preserving the folder structure:
   - `fetch_tenders.py`
   - `.github/workflows/daily-ted-check.yml`
   - `README.md` (this file)
3. Go to the repo's **Actions** tab and enable workflows if prompted.
4. Optionally, click **Run workflow** on "Daily TED tender check" to trigger
   an immediate first run rather than waiting for 05:00 UTC, and check the
   run log for errors (see note below).
5. Tell Claude (in the Cowork conversation) your repo's `owner/name` — it
   needs that to finish wiring up the daily email step, which reads:
   `https://raw.githubusercontent.com/<owner>/<repo>/main/data/latest.json`

## Known risk / what to check on the first run

TED's exact expert-query syntax and response field names could not be
verified against a live call while this was written (the environment that
generated this script had no outbound access to `api.ted.europa.eu`). If the
first Actions run fails, open the run log — TED's API returns a
`{"message": ...}` error body that usually says exactly what's wrong (e.g. a
bad operator or field name). Bring that message back to Claude to get
`fetch_tenders.py` adjusted; the rest of the pipeline (dedup via
`data/seen.json`, the email step) does not need to change.
