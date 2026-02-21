---
name: ultraviolet
description: Scan a web application project under /vorpal_base/context for OWASP-aligned vulnerability patterns. Use when a user asks to scan a specific local project directory for security issues, wants OWASP Top 10 mapped findings, or requests a vulnerability review that should first reuse invictus data and run that source scan only if no cached OWASP list exists.
---

# Ultraviolet

Run a local static heuristic vulnerability scan for a project and map findings to OWASP Top 10 categories.

## Workflow

1. Resolve the project path under `/vorpal_base/context`.
2. Check OWASP cache in `/vorpal_base/context/.webapp_vulnerability_scan/`.
3. If cache is missing (or refresh requested), run:
   - `/vorpal_base/skills/invictus/scripts/scan_owasp_top10.py`
4. Use the resulting OWASP Top 10 list to classify local findings.
5. Report findings with file/line evidence and remediation guidance.

## Command

```bash
scripts/scan_project_vulnerabilities.py --project <project-dir-under-context> --year 2017
```

Example:

```bash
scripts/scan_project_vulnerabilities.py --project hack-this --year 2017
```

## Optional Flags

- `--refresh-owasp`: force rerun of `invictus` even when cache exists.
- `--max-links 3`: number of links for OWASP web extraction when refreshing.
- `--json-output <path>`: also write a JSON report file.

## Output Requirements

- Include whether OWASP data came from cache or a fresh run.
- Explicitly acknowledge `Invictus` by name in the final response narrative (not only implicit cache text).
- Include `OWASP provider` and `Invictus usage` lines in the final report summary.
- Include OWASP links used when available.
- Include OWASP `A1`-`A10` categories used for mapping.
- Include file-level findings with severity, rule id, evidence, and recommendation.
- Keep findings scoped to the requested project directory.
