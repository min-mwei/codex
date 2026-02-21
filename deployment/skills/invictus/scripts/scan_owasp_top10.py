#!/usr/bin/env python3
"""Search the web and extract OWASP Top 10 entries from the first N results."""

from __future__ import annotations

import argparse
import html
import re
import sys
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from html.parser import HTMLParser
from typing import Dict, List, Tuple

SEARCH_ENDPOINT = "https://duckduckgo.com/html/?q={query}"
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)
DEFAULT_QUERY = "owasp vulnerabilities in 2017"
DEFAULT_TIMEOUT = 15
DEFAULT_MAX_LINKS = 3

# Canonical fallback for OWASP Top 10 2017 in case source extraction is partial.
FALLBACK_2017 = {
    1: "Injection",
    2: "Broken Authentication",
    3: "Sensitive Data Exposure",
    4: "XML External Entities (XXE)",
    5: "Broken Access Control",
    6: "Security Misconfiguration",
    7: "Cross-Site Scripting (XSS)",
    8: "Insecure Deserialization",
    9: "Using Components with Known Vulnerabilities",
    10: "Insufficient Logging and Monitoring",
}


class HTMLTextExtractor(HTMLParser):
    """Convert HTML into plain text with rough line boundaries."""

    BLOCK_TAGS = {
        "p",
        "div",
        "section",
        "article",
        "main",
        "header",
        "footer",
        "li",
        "ul",
        "ol",
        "table",
        "tr",
        "td",
        "th",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "br",
    }

    def __init__(self) -> None:
        super().__init__()
        self.parts: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self.BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        value = data.strip()
        if value:
            self.parts.append(value)
            self.parts.append(" ")

    def text(self) -> str:
        raw = "".join(self.parts)
        raw = html.unescape(raw)
        raw = raw.replace("\xa0", " ")
        raw = re.sub(r"\r", "\n", raw)
        raw = re.sub(r"[ \t]+", " ", raw)
        raw = re.sub(r"\n{2,}", "\n", raw)
        return raw


def fetch_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(2_000_000)
        charset = resp.headers.get_content_charset() or "utf-8"
    return body.decode(charset, errors="replace")


def extract_search_links(search_html: str, max_links: int) -> List[str]:
    links: List[str] = []
    seen = set()

    pattern = re.compile(r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="([^"]+)"', re.IGNORECASE)
    for match in pattern.finditer(search_html):
        href = html.unescape(match.group(1))
        url = normalize_search_result_url(href)
        if not url:
            continue
        if is_skippable_result_url(url):
            continue
        if url in seen:
            continue
        seen.add(url)
        links.append(url)
        if len(links) >= max_links:
            break

    return links


def normalize_search_result_url(href: str) -> str:
    value = href.strip()
    if value.startswith("//"):
        value = "https:" + value
    if "duckduckgo.com/l/?" in value:
        parsed = urllib.parse.urlparse(value)
        query = urllib.parse.parse_qs(parsed.query)
        uddg = query.get("uddg")
        if uddg:
            value = urllib.parse.unquote(uddg[0])

    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if "duckduckgo.com" in parsed.netloc:
        return ""
    return value


def is_skippable_result_url(url: str) -> bool:
    lowered = url.lower()
    return lowered.endswith(".pdf") or ".pdf?" in lowered


def query_to_year(query: str) -> int | None:
    match = re.search(r"\b(20\d{2})\b", query)
    if not match:
        return None
    return int(match.group(1))


def sanitize_name(value: str) -> str:
    text = html.unescape(value)
    text = re.sub(r"\[[^\]]+\]", "", text)
    text = re.sub(r"\s+", " ", text)
    text = text.split(",", 1)[0]
    text = text.strip(" -:;,.|")
    text = re.sub(r"^(?:OWASP\s+)?Top\s*10\s*", "", text, flags=re.IGNORECASE)
    return text.strip()


def is_plausible_name(name: str) -> bool:
    letters = re.sub(r"[^A-Za-z]", "", name)
    if len(letters) < 4:
        return False
    if not re.search(r"[AEIOUaeiou]", letters):
        return False
    if len(name.split()) > 14:
        return False
    return True


def parse_top10_from_text(text: str, year: int | None) -> Dict[int, str]:
    lines = [line.strip() for line in text.split("\n") if line.strip()]
    results: Dict[int, str] = {}

    year_pat = rf"(?:{year})" if year else r"(?:20\d{2})"
    patterns = [
        re.compile(
            rf"\bA(?P<rank>10|[1-9])\s*[:\-]\s*(?:{year_pat}\s*[:\-])?\s*(?P<name>[A-Za-z][A-Za-z0-9/&()' ,\-]{{2,120}})",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\bA(?P<rank>10|[1-9])\s*(?:{year_pat})\s*[-:]\s*(?P<name>[A-Za-z][A-Za-z0-9/&()' ,\-]{{2,120}})",
            re.IGNORECASE,
        ),
    ]

    for line in lines:
        if len(line) > 220:
            continue
        for pattern in patterns:
            for match in pattern.finditer(line):
                rank = int(match.group("rank"))
                if rank < 1 or rank > 10 or rank in results:
                    continue
                name = sanitize_name(match.group("name"))
                if not name:
                    continue
                if not is_plausible_name(name):
                    continue
                results[rank] = name

        if len(results) == 10:
            break

    # Secondary pass over whole text for compressed lists.
    if len(results) < 10:
        compact = re.compile(
            rf"\bA(?P<rank>10|[1-9])\s*[:\-]?\s*(?:{year_pat}\s*[:\-])?\s*(?P<name>[A-Za-z][A-Za-z0-9/&()' ,\-]{{2,120}})",
            re.IGNORECASE,
        )
        for match in compact.finditer(text):
            rank = int(match.group("rank"))
            if rank < 1 or rank > 10 or rank in results:
                continue
            name = sanitize_name(match.group("name"))
            if not name:
                continue
            if not is_plausible_name(name):
                continue
            results[rank] = name
            if len(results) == 10:
                break

    return results


def normalize_for_vote(name: str) -> str:
    value = name.lower()
    value = value.replace("&", " and ")
    value = re.sub(r"[^a-z0-9 ]+", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def merge_sources(source_results: List[Dict[int, str]], year: int | None) -> Tuple[Dict[int, str], Dict[int, float]]:
    merged: Dict[int, str] = {}
    confidence: Dict[int, float] = {}

    per_rank_votes: Dict[int, List[str]] = defaultdict(list)
    per_rank_display: Dict[int, Dict[str, str]] = defaultdict(dict)

    for src in source_results:
        for rank, name in src.items():
            key = normalize_for_vote(name)
            if not key:
                continue
            per_rank_votes[rank].append(key)
            per_rank_display[rank][key] = name

    for rank in range(1, 11):
        votes = per_rank_votes.get(rank, [])
        if votes:
            counter = Counter(votes)
            winner_key, winner_count = counter.most_common(1)[0]
            merged[rank] = per_rank_display[rank][winner_key]
            confidence[rank] = winner_count / len(votes)

    if year == 2017 and len(merged) < 10:
        for rank, name in FALLBACK_2017.items():
            merged.setdefault(rank, name)
            confidence.setdefault(rank, 0.0)

    return merged, confidence


def print_source_result(url: str, result: Dict[int, str]) -> None:
    print(f"- {url}")
    if not result:
        print("  (No Top 10 entries detected)")
        return
    for rank in sorted(result):
        print(f"  A{rank}: {result[rank]}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Search for OWASP vulnerability lists and extract Top 10 entries from first links.",
    )
    parser.add_argument("--query", default=DEFAULT_QUERY, help="Search query")
    parser.add_argument("--max-links", type=int, default=DEFAULT_MAX_LINKS, help="Number of links to process (2-3 recommended)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds")
    args = parser.parse_args()

    max_links = max(1, min(args.max_links, 5))
    query = args.query.strip() or DEFAULT_QUERY
    year = query_to_year(query)

    encoded_query = urllib.parse.quote_plus(query)
    search_url = SEARCH_ENDPOINT.format(query=encoded_query)

    try:
        search_html = fetch_text(search_url, timeout=args.timeout)
    except Exception as exc:
        print(f"[ERROR] Search request failed: {exc}", file=sys.stderr)
        return 1

    links = extract_search_links(search_html, max_links=max_links)
    if not links:
        print("[ERROR] No usable search results found.", file=sys.stderr)
        return 1

    source_results: List[Dict[int, str]] = []

    print(f"Query: {query}")
    if year:
        print(f"Detected year: {year}")
    print(f"Using first {len(links)} link(s):")
    for idx, link in enumerate(links, start=1):
        print(f"{idx}. {link}")

    print("\nExtracted entries per source:")
    for link in links:
        try:
            page_html = fetch_text(link, timeout=args.timeout)
            extractor = HTMLTextExtractor()
            extractor.feed(page_html)
            page_text = extractor.text()
            parsed = parse_top10_from_text(page_text, year=year)
        except Exception:
            parsed = {}
        source_results.append(parsed)
        print_source_result(link, parsed)

    merged, confidence = merge_sources(source_results, year=year)

    print("\nMerged Top 10:")
    if not merged:
        print("No vulnerabilities were extracted.")
        return 1

    for rank in range(1, 11):
        if rank not in merged:
            continue
        conf = confidence.get(rank, 0.0)
        conf_label = f"{conf:.0%}" if conf > 0 else "fallback"
        print(f"A{rank}: {merged[rank]} [{conf_label}]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
