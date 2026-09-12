#!/usr/bin/env python3
"""Check that every quote in baseline/rules.yaml still appears, verbatim, on the page it cites.

Pages are fetched as Markdown where the vendor serves it (docs pages + ".md"), links are reduced to
their text, whitespace is collapsed, and the quote must be a substring. Writes results/sources.json
and exits non-zero if any quote is missing.

    python3 tools/verify_sources.py
"""
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_HOSTS = ("https://code.claude.com/docs/", "https://developers.openai.com/codex/")


GHSA = re.compile(r"https://github.com/([^/]+/[^/]+)/security/advisories/(GHSA-[\w-]+)")


def get(url, hops=5):
    """GET following redirects, including 308, which urllib in Python 3.9 does not follow."""
    req = urllib.request.Request(url, headers={"User-Agent": "baseline-source-check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308) and hops and e.headers.get("Location"):
            return get(urllib.parse.urljoin(url, e.headers["Location"]), hops - 1)
        raise


def fetch(url):
    m = GHSA.match(url)
    if m:  # the advisory's own Markdown text, from the GitHub API
        return json.loads(get(f"https://api.github.com/repos/{m[1]}/security-advisories/{m[2]}"))["description"]
    return get(url + ".md" if url.startswith(MARKDOWN_HOSTS) else url)


def normalise(text):
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)  # [text](url) -> text
    text = text.replace("\\", "").replace("*", "")
    text = text.replace("&quot;", '"').replace("&#x27;", "'").replace("&amp;", "&")
    return re.sub(r"\s+", " ", text).strip()


def main():
    rules = yaml.safe_load((ROOT / "baseline/rules.yaml").read_text())["rules"]
    pages, results = {}, []
    for rule in rules:
        for src in rule.get("sources", []):
            url = src["url"]
            if url not in pages:
                try:
                    pages[url] = normalise(fetch(url))
                except Exception as e:
                    pages[url] = None
                    print(f"cannot fetch {url}: {e}", file=sys.stderr)
            found = pages[url] is not None and normalise(src["quote"]) in pages[url]
            results.append({"rule": rule["id"], "url": url, "found": found,
                            "fetched": pages[url] is not None, "quote": src["quote"]})
    out = ROOT / "results/sources.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"checked": str(date.today()), "quotes": results}, indent=1, ensure_ascii=False) + "\n")
    missing = [r for r in results if not r["found"]]
    for r in missing:
        print(f"MISSING {r['rule']} {r['url']}\n   {r['quote']}")
    print(f"{len(results) - len(missing)}/{len(results)} quotes found")
    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    main()
