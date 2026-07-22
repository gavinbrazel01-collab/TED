#!/usr/bin/env python3
"""
Daily TED (Tenders Electronic Daily) watcher for OSINT / link-analysis /
digital-forensics / data-fusion / criminal-intelligence platform tenders.
 
What this does:
  1. Queries the public TED Search API (https://api.ted.europa.eu/v3/notices/search)
     twice: once by CPV classification code, once by full-text keyword (across EN/DE/
     FR/ES/IT/HU/PL/NL/PT), both restricted to a trailing publication-date window.
  2. Merges + de-duplicates the two result sets by notice ID.
  3. Compacts each raw notice down to a small, fixed set of fields (id, title, buyer,
     country, cpv, deadline, publication date, url, which keywords matched) --
     regardless of what TED's raw payload actually contains, since the exact shape
     of that payload could not be verified live while this was written.
  4. Cross-checks against data/seen.json (a running list of notice IDs we've already
     surfaced) so only genuinely NEW notices are reported each run.
  5. Writes data/latest.json (today's new candidates, for the downstream email step),
     data/debug_last_raw_sample.json (one untouched raw notice, for debugging field
     names if something looks wrong), and updates data/seen.json.
 
KNOWN RISK: TED's expert-query operator syntax (`~`, `=`, `IN (...)`) is built from
the officially documented request schema (query/fields/page/limit/scope/
paginationMode) plus TED website conventions, but could not be verified against a
live call while writing this (no outbound access to api.ted.europa.eu from that
environment). If a run's log shows a TED API error, the error body usually says
exactly what's wrong -- bring it back to get the query strings adjusted. The
compaction step below is deliberately defensive (tries many possible key names) so
that even if the `fields` list isn't fully honored by TED, output size stays small
and usable.
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
 
# Safety caps so a single run can never blow up file size / run time.
MAX_PAGES_PER_QUERY = 10
PAGE_LIMIT = 100
MAX_NEW_NOTICES_OUTPUT = 300
TEXT_FIELD_MAX_CHARS = 400
 
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
 
# Requested field allowlist. TED may or may not honor this fully -- the
# compaction step below does not trust it and re-extracts defensively from
# whatever actually comes back.
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
DEBUG_SAMPLE_PATH = os.path.join(DATA_DIR, "debug_last_raw_sample.json")
 
 
def _post(query: str, page: int = 1, limit: int = PAGE_LIMIT):
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
        print(f"TED API error {e.code} for query={query!r}:\n{err_body[:2000]}", file=sys.stderr)
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
 
 
def _fetch_all(query: str, max_pages: int = MAX_PAGES_PER_QUERY):
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
 
 
def _first(raw: dict, *keys):
    for k in keys:
        v = raw.get(k)
        if v not in (None, "", [], {}):
            return v
    return None
 
 
def _as_text(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v[:TEXT_FIELD_MAX_CHARS]
    if isinstance(v, dict):
        for lang in ("eng", "en", "ENG", "EN"):
            if lang in v:
                return str(v[lang])[:TEXT_FIELD_MAX_CHARS]
        for val in v.values():
            return str(val)[:TEXT_FIELD_MAX_CHARS]
        return None
    if isinstance(v, list):
        return ", ".join(str(x) for x in v[:5])[:TEXT_FIELD_MAX_CHARS]
    return str(v)[:TEXT_FIELD_MAX_CHARS]
 
 
def _extract_url(raw: dict, pub_number):
    links = raw.get("links")
    if isinstance(links, dict):
        for key in ("html", "pdf", "xml", "self"):
            v = links.get(key)
            if isinstance(v, dict):
                for lang in ("ENG", "eng", "en", "EN"):
                    if lang in v:
                        return v[lang]
                for val in v.values():
                    return val
            elif isinstance(v, str):
                return v
    if pub_number:
        return f"https://ted.europa.eu/en/notice/-/detail/{pub_number}"
    return None
 
 
def notice_id(raw: dict) -> str:
    pub_number = _first(
        raw, "publication-number", "publicationNumber", "ND", "notice-id", "id"
    )
    if pub_number:
        return str(pub_number)
    # Last resort: hash of the raw content so we still dedupe consistently.
    return str(hash(json.dumps(raw, sort_keys=True)))
 
 
def compact_notice(raw: dict, matched_via) -> dict:
    """Reduce a raw TED notice (whatever shape it actually came in) down to a
    small fixed set of fields, so output size stays bounded regardless of
    what TED's API returns."""
    blob_lower = json.dumps(raw, ensure_ascii=False).lower()
    matched_keywords = sorted({kw for kw in ALL_KEYWORDS if kw.lower() in blob_lower})
 
    pub_number = _first(
        raw, "publication-number", "publicationNumber", "ND", "notice-id", "id"
    )
    cpv = _first(raw, "classification-cpv", "cpvs", "cpv")
    if isinstance(cpv, list):
        cpv = [str(c)[:20] for c in cpv[:10]]
    elif cpv is not None:
        cpv = [str(cpv)[:20]]
 
    return {
        "id": str(pub_number) if pub_number else notice_id(raw),
        "title": _as_text(_first(raw, "notice-title", "title", "title-proc")),
        "buyer": _as_text(_first(raw, "buyer-name", "buyerName", "organisation-name-buyer")),
        "country": _as_text(_first(raw, "buyer-country", "buyerCountry", "country")),
        "cpv": cpv,
        "notice_type": _as_text(_first(raw, "notice-type", "noticeType", "form-type")),
        "publication_date": _as_text(_first(raw, "publication-date", "publicationDate")),
        "deadline": _as_text(_first(raw, "deadline-date-lot", "deadline", "deadlineReceiptRequest")),
        "url": _extract_url(raw, pub_number),
        "matched_via": sorted(set(matched_via)),
        "matched_keywords": matched_keywords,
    }
 
 
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
 
    # Save one untouched raw sample for debugging field names, without ever
    # persisting the full raw payload for every notice.
    sample = (cpv_hits or kw_hits or [None])[0]
    if sample is not None:
        save_json(DEBUG_SAMPLE_PATH, sample)
 
    merged_via = {}
    merged_raw = {}
    for n in cpv_hits:
        nid = notice_id(n)
        merged_raw[nid] = n
        merged_via.setdefault(nid, set()).add("cpv")
    for n in kw_hits:
        nid = notice_id(n)
        merged_raw.setdefault(nid, n)
        merged_via.setdefault(nid, set()).add("keyword")
 
    seen = load_seen()
    today_str = date.today().isoformat()
 
    new_ids = [nid for nid in merged_raw if nid not in seen]
    new_compact = [
        compact_notice(merged_raw[nid], merged_via[nid]) for nid in new_ids
    ]
    new_compact = new_compact[:MAX_NEW_NOTICES_OUTPUT]
 
    # Update seen.json with everything we saw today (new + repeats), pruning
    # entries older than ~120 days to keep the file small.
    for nid in merged_raw:
        seen[nid] = today_str
    cutoff = (date.today() - timedelta(days=120)).isoformat()
    seen = {nid: d for nid, d in seen.items() if d >= cutoff}
 
    save_json(SEEN_PATH, seen)
    save_json(LATEST_PATH, {
        "run_date": today_str,
        "lookback_days": LOOKBACK_DAYS,
        "total_candidates_this_run": len(merged_raw),
        "new_notices": new_compact,
    })
 
    print(f"Fetched {len(cpv_hits)} CPV hits, {len(kw_hits)} keyword hits, "
          f"{len(merged_raw)} unique, {len(new_compact)} new since last run.")
 
 
if __name__ == "__main__":
    main()
 
