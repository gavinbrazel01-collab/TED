#!/usr/bin/env python3
"""
Daily TED (Tenders Electronic Daily) watcher for OSINT / link-analysis /
digital-forensics / data-fusion / criminal-intelligence platform tenders.

What this does:
  1. Queries the public TED Search API (https://api.ted.europa.eu/v3/notices/search)
     twice: once by CPV classification code, once by full-text keyword (across EN/DE/
     FR/ES/IT/HU/PL/NL/PT), both restricted to a trailing publication-date window.
  2. Merges + de-duplicates the two result sets by publication number.
  3. Cross-checks against data/seen.json (a running list of notice IDs we've already
     surfaced) so only genuinely NEW notices are reported each run.
  4. Writes data/latest.json (today's new candidates, for the downstream email step)
     and updates data/seen.json (so tomorrow's run doesn't re-report them).

IMPORTANT / KNOWN RISK:
  TED's expert-query syntax (operators like `~`, `IN (...)`, wildcards) and the exact
  response field names are not fully documented in a way I could verify from inside
  this sandbox (outbound network access there is restricted, so I could not run a
  live test call while writing this). The query below is built from the officially
  documented request schema (query / fields / page / limit / scope / paginationMode)
  plus the expert-query conventions used on the TED website. If the first run in
  GitHub Actions fails, check the Action log for the API's error message (TED
  usually returns a helpful `{"message": ...}` body) and adjust QUERY_CPV /
  QUERY_KEYWORDS below accordingly -- the rest of the pipeline (dedup, filtering,
  output format) does not need to change.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import date, timedelta

SEARCH_URL = "https://api.ted.europa.eu/v3/notices/search"

# How many days back to ask TED for, each run. Generous overlap because TED's own
# publication pipeline can lag a day or two; true "new" filtering happens via
# data/seen.json, not this window.
LOOKBACK_DAYS = 5

# ---------------------------------------------------------------------------
# Search criteria (from the user's brief)
# ---------------------------------------------------------------------------

CPV_PREFIXES = [
    "7220", "7221", "7223", "7226", "7228",
    "48000000", "48100000", "48730000", "48800000",
]

# Expand short prefixes to the concrete 8-digit CPV divisions they refer to
# (72200000 Software programming & consultancy, 72210000 Programming services of
# packaged software, 72230000 Custom software development, 72260000
# Software-related services, 72280000 Data processing services) -- plus the
# already-8-digit codes given as-is.
CPV_EXPANDED = sorted(set([
    "72200000", "72210000", "72230000", "72260000", "72280000",
    "48000000", "48100000", "48730000", "48800000",
]))

KEYWORDS_BY_LANG = {
    "EN": [
        "software development", "custom software", "web application development",
        "mobile application development", "API development", "system integration",
        "investigative intelligence", "OSINT", "link analysis",
        "criminal intelligence platform", "data fusion",
        "digital forensics analysis software",
    ],
    "DE": [
        "Softwareentwicklung", "individuelle Softwareentwicklung",
        "Webanwendungsentwicklung", "Systemintegration", "OSINT",
        "Ermittlungsauswertung", "kriminalpolizeiliche Analyseplattform",
        "Verknüpfungsanalyse", "Datenfusion", "digitale forensische Analysesoftware",
    ],
    "FR": [
        "développement de logiciels", "développement d'applications web",
        "intégration de systèmes", "OSINT", "renseignement d'enquête",
        "analyse de liens", "plateforme de renseignement criminel",
        "fusion de données", "logiciel d'analyse forensique numérique",
    ],
    "ES": [
        "desarrollo de software", "desarrollo de aplicaciones web",
        "integración de sistemas", "OSINT", "inteligencia investigativa",
        "análisis de vínculos", "plataforma de inteligencia criminal",
        "fusión de datos", "software de análisis forense digital",
    ],
    "IT": [
        "sviluppo software", "sviluppo di applicazioni web",
        "integrazione di sistemi", "OSINT", "intelligence investigativa",
        "analisi dei collegamenti", "piattaforma di intelligence criminale",
        "fusione dei dati", "software di analisi forense digitale",
    ],
    "HU": [
        "szoftverfejlesztés", "webalkalmazás-fejlesztés", "rendszerintegráció",
        "OSINT", "nyomozati hírszerzés", "kapcsolatelemzés",
        "bűnügyi hírszerzési platform", "adatfúzió",
        "digitális igazságügyi elemző szoftver",
    ],
    "PL": [
        "rozwój oprogramowania", "oprogramowanie na zamówienie",
        "tworzenie aplikacji internetowych", "integracja systemów", "OSINT",
        "wywiad śledczy", "analiza powiązań", "platforma wywiadu kryminalnego",
        "fuzja danych", "oprogramowanie do analizy kryminalistyki cyfrowej",
    ],
    "NL": [
        "softwareontwikkeling", "maatwerksoftware",
        "ontwikkeling van webapplicaties", "systeemintegratie", "OSINT",
        "opsporingsinlichtingen", "linkanalyse",
        "platform voor criminele inlichtingen", "datafusie",
        "software voor digitaal forensisch onderzoek",
    ],
    "PT": [
        "desenvolvimento de software", "desenvolvimento de aplicações web",
        "integração de sistemas", "OSINT", "inteligência de investigação",
        "análise de vínculos", "plataforma de inteligência criminal",
        "fusão de dados", "software de análise forense digital",
    ],
}

ALL_KEYWORDS = sorted({kw for kws in KEYWORDS_BY_LANG.values() for kw in kws})

FIELDS = [
    "publication-number",
    "notice-title",
    "buyer-name",
    "buyer-country",
    "classification-cpv",
    "deadline-date-lot",
    "publication-date",
    "notice-type",
    "links",
]

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
SEEN_PATH = os.path.join(DATA_DIR, "seen.json")
LATEST_PATH = os.path.join(DATA_DIR, "latest.json")


def _post(query: str, page: int = 1, limit: int = 250):
    body = json.dumps({
        "query": query,
        "fields": FIELDS,
        "page": page,
        "limit": limit,
        "scope": "ALL",
        "paginationMode": "PAGE_NUMBER",
        "checkQuerySyntax": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        SEARCH_URL,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"TED API error {e.code} for query={query!r}:\n{err_body}", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print(f"Network error calling TED API: {e}", file=sys.stderr)
        raise


def _date_window():
    end = date.today()
    start = end - timedelta(days=LOOKBACK_DAYS)
    return start.strftime("%Y%m%d"), end.strftime("%Y%m%d")


def fetch_by_cpv():
    start, end = _date_window()
    cpv_clause = " OR ".join(f'classification-cpv={code}' for code in CPV_EXPANDED)
    query = f"({cpv_clause}) AND publication-date>={start} AND publication-date<={end}"
    return _fetch_all(query)


def fetch_by_keyword():
    start, end = _date_window()
    kw_clause = " OR ".join(f'FT~"{kw}"' for kw in ALL_KEYWORDS)
    query = f"({kw_clause}) AND publication-date>={start} AND publication-date<={end}"
    return _fetch_all(query)


def _fetch_all(query: str, max_pages: int = 10):
    results = []
    page = 1
    while page <= max_pages:
        data = _post(query, page=page)
        notices = data.get("notices") or data.get("results") or []
        if not notices:
            break
        results.extend(notices)
        total = data.get("totalNoticeCount") or data.get("total") or 0
        if len(results) >= total or not notices:
            break
        page += 1
        time.sleep(1)  # be polite to the public API
    return results


def notice_id(n: dict) -> str:
    return str(
        n.get("publication-number")
        or n.get("publicationNumber")
        or n.get("id")
        or json.dumps(n, sort_keys=True)
    )


def load_seen():
    if os.path.exists(SEEN_PATH):
        with open(SEEN_PATH) as f:
            return json.load(f)
    return {}


def save_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=True)


def main():
    try:
        cpv_hits = fetch_by_cpv()
    except Exception:
        cpv_hits = []
        print("CPV query failed, continuing with keyword-only results.", file=sys.stderr)

    try:
        kw_hits = fetch_by_keyword()
    except Exception:
        kw_hits = []
        print("Keyword query failed, continuing with CPV-only results.", file=sys.stderr)

    merged = {}
    for n in cpv_hits:
        merged[notice_id(n)] = {**n, "_matched_via": ["cpv"]}
    for n in kw_hits:
        nid = notice_id(n)
        if nid in merged:
            merged[nid]["_matched_via"].append("keyword")
        else:
            merged[nid] = {**n, "_matched_via": ["keyword"]}

    seen = load_seen()
    today_str = date.today().isoformat()

    new_notices = {nid: n for nid, n in merged.items() if nid not in seen}

    # Update seen.json with everything we saw today (new + repeats), pruning
    # entries older than ~120 days to keep the file small.
    for nid in merged:
        seen[nid] = today_str
    cutoff = (date.today() - timedelta(days=120)).isoformat()
    seen = {nid: d for nid, d in seen.items() if d >= cutoff}

    save_json(SEEN_PATH, seen)
    save_json(LATEST_PATH, {
        "run_date": today_str,
        "lookback_days": LOOKBACK_DAYS,
        "total_candidates_this_run": len(merged),
        "new_notices": list(new_notices.values()),
    })

    print(f"Fetched {len(cpv_hits)} CPV hits, {len(kw_hits)} keyword hits, "
          f"{len(merged)} unique, {len(new_notices)} new since last run.")


if __name__ == "__main__":
    main()
