---
name: patch-project
description: Generate review-ready patch bundles for projects under /vorpal_base/context by consuming ultraviolet and cobalt vulnerability findings, then mapping high-risk findings to concrete code changes (with DVWA-aware hardening templates). Use when a user asks to turn scan findings into actionable patch diffs for review before merge/apply.
---

# Patch Project

Turn vulnerability scan results into a patch set that can be code-reviewed before applying to the project.

## Workflow

1. Resolve target project path under `/vorpal_base/context`.
2. Load `ultraviolet` and `cobalt` JSON findings (or run those tools to generate fresh reports).
3. Prioritize high-severity findings and group them by affected module/file.
4. Generate patch candidates:
   - DVWA-aware hardening replacement for vulnerable `source/low.php` files.
   - Generic inline review comments for non-DVWA files when exact auto-fix is unsafe.
5. Emit review bundle:
   - unified diff patch
   - structured JSON summary
   - optional patched file snapshots
6. Apply patches only when explicitly requested.

## Command

```bash
scripts/generate_review_patch.py --project DVWA --target http://127.0.0.1:8080
```

## Optional Flags

- `--ultraviolet-report <path>`: use an existing ultraviolet JSON report.
- `--cobalt-report <path>`: use an existing cobalt JSON report.
- `--target <url>`: required to auto-run cobalt when report is missing.
- `--refresh-scans`: rerun ultraviolet/cobalt even if cached reports exist.
- `--refresh-owasp`: pass OWASP refresh through to ultraviolet/cobalt.
- `--skip-cobalt`: generate patches from ultraviolet only.
- `--year 2017`: OWASP year for upstream scans.
- `--max-links 3`: OWASP links to parse for upstream scans.
- `--apply`: apply generated edits directly to project files.
- `--output-dir <path>`: override bundle output directory.
- `--json-output <path>`: write patch summary JSON to an explicit path.

## Output Requirements

- Include report provenance (provided vs generated) for ultraviolet and cobalt.
- Include findings that triggered each patch.
- Include file-level patch strategies and diff statistics.
- Write unified diff as `proposed.patch` for review.
- Keep edits scoped to the selected project.
