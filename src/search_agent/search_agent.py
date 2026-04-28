import requests
from bs4 import BeautifulSoup
import re
import json
import sys
import time
from urllib.parse import quote_plus


def duckduckgo_search(query, num_results=10):
    """
    Perform a DuckDuckGo HTML search for the query and scrape top results.
    Uses the `html.duckduckgo.com/html` endpoint to avoid heavy JS.
    """
    search_url = f"https://html.duckduckgo.com/html?q={quote_plus(query)}"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; PhantomOperator/1.0)"}
    resp = requests.post(search_url, data={"q": query}, headers=headers, timeout=15)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    results = []

    # DuckDuckGo's HTML endpoint uses <a class="result__a"> for titles/links in many cases,
    # but pages vary; we'll be defensive and pick plausible anchors.
    anchors = soup.find_all('a')
    for a in anchors:
        href = a.get('href')
        title = a.get_text().strip()
        if not href or not title:
            continue
        # Heuristic: skip anchors that are navigation or hashes
        if href.startswith('#') or href.startswith('/y.js'):
            continue
        # Keep only a reasonable number of results
        results.append({"title": title, "link": href, "description": ""})
        if len(results) >= num_results:
            break

    # Try to extract snippets/descriptions
    snippets = soup.select('.result__snippet')
    for i, s in enumerate(snippets):
        if i < len(results):
            results[i]['description'] = s.get_text().strip()

    return results


def analyze_threats(search_results):
    """
    Very simple heuristic-based threat analysis.
    Marks `critical` if phone numbers or email addresses are found.
    Marks `high` if keywords like 'address', 'ssn', 'social security', 'leak' appear.
    Otherwise `benign`.
    """
    threats = []
    phone_re = re.compile(r"\b\d{3}[\-\.\s]?\d{3}[\-\.\s]?\d{4}\b")
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    sensitive_keywords = ["address", "social security", "ssn", "leak", "date of birth"]

    for r in search_results:
        desc = (r.get('description') or "").lower()
        title = (r.get('title') or "")
        combined = f"{title}\n{desc}"

        level = "benign"
        reasons = []

        if phone_re.search(combined):
            level = "critical"
            reasons.append("phone_number_detected")
        if email_re.search(combined) and level != 'critical':
            level = "high"
            reasons.append("email_detected")
        for kw in sensitive_keywords:
            if kw in combined:
                if level == 'benign':
                    level = 'high'
                reasons.append(f"keyword:{kw}")

        threats.append({
            "title": r.get('title'),
            "link": r.get('link'),
            "description": r.get('description'),
            "threat_level": level,
            "reasons": reasons,
        })

    return threats


def save_results(query, analysis):
    fname = f"{query.replace(' ', '_')}_threat_analysis.json"
    with open(fname, 'w', encoding='utf-8') as fh:
        json.dump(analysis, fh, indent=2, ensure_ascii=False)
    return fname


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python search_agent.py \"Full Name\"")
        sys.exit(1)

    query = " ".join(sys.argv[1:])
    print(f"Searching for '{query}' (DuckDuckGo HTML endpoint)...")
    try:
        start = time.time()
        results = duckduckgo_search(query, num_results=10)
        print(f"Found {len(results)} raw results in {time.time()-start:.2f}s")

        print("Analyzing threats...")
        analysis = analyze_threats(results)

        out = save_results(query, analysis)
        print(f"Threat analysis saved to {out}")
    except Exception as e:
        print("Error during search/analysis:", e)
        sys.exit(2)
