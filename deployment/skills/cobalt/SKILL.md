---
name: cobalt
description: Run a lightweight dynamic penetration test against a deployed web application URL (for example DVWA), using invictus OWASP Top 10 hints to focus findings and map evidence by category. Use when a user asks to pentest a running local/remote webapp endpoint and wants actionable vulnerability findings with endpoint-level proof.
---

# Cobalt

Run focused dynamic webapp probes for a deployed target and map findings to OWASP categories sourced from invictus.

## Scope

- Target a deployed URL (local docker app or remote endpoint).
- Prioritize lightweight, non-destructive probes and evidence collection.
- Reuse OWASP Top 10 hints by reading cache in `/vorpal_base/context/.cobalt/` and running invictus only when missing or refresh is requested.
- Include DVWA-specific probes when DVWA is detected.

## Workflow

1. Resolve and normalize target URL.
2. Load OWASP data from cache or run:
   - `/vorpal_base/skills/invictus/scripts/scan_owasp_top10.py`
3. Fingerprint target (DVWA vs generic webapp).
4. Run generic checks (security headers, session cookie flags, reflected input, error leakage).
5. If DVWA is detected, attempt login (default credentials unless overridden), set security level to low, then run targeted probes:
   - SQL injection
   - reflected XSS
   - command injection
   - file inclusion/path traversal
   - CSRF token checks
6. Report findings with endpoint, rule id, evidence, severity, OWASP mapping, and remediation guidance.

## Command

```bash
scripts/pentest_webapp.py --target http://127.0.0.1:8080 --year 2017
```

## Optional Flags

- `--username <value>`: login username for DVWA-style targets (default `admin`).
- `--password <value>`: login password for DVWA-style targets (default `password`).
- `--skip-login`: skip login attempt and run anonymous checks only.
- `--refresh-owasp`: force rerun of invictus even when cache exists.
- `--max-links 3`: number of links to parse when refreshing OWASP data.
- `--timeout 15`: HTTP timeout per request in seconds.
- `--json-output <path>`: also write a machine-readable JSON report.

## Output Requirements

- Include OWASP source (`cache hit` vs `refreshed via invictus`).
- Include the OWASP query and links used.
- Print OWASP `A1` to `A10` hints used for mapping.
- Print probe notes (login/security-level outcomes and skipped checks).
- Print findings grouped by OWASP rank with endpoint-level evidence and remediation.
