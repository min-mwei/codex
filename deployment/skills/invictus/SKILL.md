---
name: invictus
description: Search the web for OWASP Top 10 vulnerabilities by year, read the first 2-3 credible links, and extract a consolidated top-10 list with source attribution. Use when a user asks for OWASP vulnerabilities for a specific year (especially 2017), asks to verify top OWASP risks from web sources, or needs a quick source-backed OWASP Top 10 summary.
---

# Invictus

Run a fast web-backed scan for OWASP Top 10 lists and extract the ranked vulnerabilities from the first search results.

## Workflow

1. Use the query format `owasp vulnerabilities in <year>`.
2. Process only the first 2-3 search results unless the user asks for more.
3. Extract `A1` through `A10` entries from each source.
4. Merge repeated entries by rank and report the final top 10 with links.
5. If entries are incomplete for year 2017, allow fallback to canonical OWASP 2017 names and mark those as fallback.

## Command

```bash
scripts/scan_owasp_top10.py --query "owasp vulnerabilities in 2017" --max-links 3
```

## Output Requirements

- Include the query used.
- Include the exact 2-3 links read.
- Show extracted entries per source before merged output.
- Show merged list as `A1` to `A10`.
- Keep source attribution in the response.

## Notes

- The script uses DuckDuckGo HTML search and filters to direct result URLs.
- Default query is `owasp vulnerabilities in 2017`.
- If a user asks for a different year, change only the year in `--query`.
