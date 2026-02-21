#!/usr/bin/env python3
"""Generate review-ready patch bundles from ultraviolet and cobalt findings."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple

CONTEXT_ROOT = Path("/vorpal_base/context").resolve()
CACHE_ROOT = CONTEXT_ROOT / ".patch_project"

ULTRAVIOLET_SCRIPT = Path(
    "/vorpal_base/skills/ultraviolet/scripts/scan_project_vulnerabilities.py"
)
COBALT_SCRIPT = Path("/vorpal_base/skills/cobalt/scripts/pentest_webapp.py")

DEFAULT_YEAR = 2017
DEFAULT_MAX_LINKS = 3

PATCHABLE_DVWA_MODULES = {"sqli", "xss_r", "exec", "fi", "csrf"}

ULTRAVIOLET_RULE_TO_MODULE = {
    "inj-dynamic-sql": "sqli",
    "xss-dom-sink": "xss_r",
    "inj-shell-true": "exec",
}

COBALT_RULE_TO_MODULE = {
    "dvwa-sqli-error": "sqli",
    "dvwa-sqli-boolean": "sqli",
    "dvwa-xss-reflected": "xss_r",
    "dvwa-command-injection": "exec",
    "dvwa-lfi-passwd": "fi",
    "dvwa-csrf-token-missing": "csrf",
}

COMMENT_STYLE_BY_SUFFIX = {
    ".py": "#",
    ".rb": "#",
    ".sh": "#",
    ".yaml": "#",
    ".yml": "#",
    ".ini": "#",
    ".conf": "#",
    ".properties": "#",
    ".js": "//",
    ".jsx": "//",
    ".ts": "//",
    ".tsx": "//",
    ".java": "//",
    ".go": "//",
    ".cs": "//",
    ".swift": "//",
    ".kt": "//",
    ".kts": "//",
    ".c": "//",
    ".cc": "//",
    ".cpp": "//",
    ".h": "//",
    ".hpp": "//",
    ".sql": "--",
    ".html": "<!--",
    ".xml": "<!--",
    ".vue": "<!--",
    ".svelte": "<!--",
}


@dataclass
class ProposedEdit:
    relative_path: str
    strategy: str
    reasons: List[str]
    before: str
    after: str


def is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def normalize_project_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", value.strip())
    return slug.strip("_") or "project"


def sanitize_relative_path(path: str) -> str | None:
    raw = path.strip().replace("\\", "/")
    if not raw:
        return None
    candidate = Path(raw)
    if candidate.is_absolute():
        return None
    if any(part == ".." for part in candidate.parts):
        return None
    normalized = candidate.as_posix().lstrip("./")
    return normalized or None


def resolve_project_path(raw_path: str) -> Tuple[Path, str]:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = CONTEXT_ROOT / candidate
    project = candidate.resolve()

    if not project.exists():
        raise ValueError(f"Project path does not exist: {project}")
    if not project.is_dir():
        raise ValueError(f"Project path is not a directory: {project}")
    if not is_within(project, CONTEXT_ROOT):
        raise ValueError(
            f"Project path must be under {CONTEXT_ROOT}. Got: {project}"
        )

    relative = project.relative_to(CONTEXT_ROOT).as_posix()
    return project, relative


def run_subprocess(cmd: List[str], label: str) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 0:
        return
    stderr = (proc.stderr or "").strip()
    stdout = (proc.stdout or "").strip()
    detail = stderr or stdout or "(no output)"
    raise RuntimeError(f"{label} failed (exit {proc.returncode}): {detail}")


def load_json(path: Path) -> Dict[str, object]:
    if not path.exists():
        raise RuntimeError(f"Report not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"Report is not a JSON object: {path}")
    return data


def ensure_ultraviolet_report(
    project: Path,
    project_ref: str,
    provided: str | None,
    *,
    refresh_scans: bool,
    refresh_owasp: bool,
    year: int,
    max_links: int,
) -> Tuple[Path, Dict[str, object], str]:
    if provided:
        report_path = Path(provided).resolve()
        return report_path, load_json(report_path), "provided"

    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    slug = normalize_project_slug(project_ref)
    report_path = CACHE_ROOT / f"ultraviolet_{slug}.json"

    if report_path.exists() and not refresh_scans:
        return report_path, load_json(report_path), "cache"

    if not ULTRAVIOLET_SCRIPT.exists():
        raise RuntimeError(f"Missing ultraviolet script: {ULTRAVIOLET_SCRIPT}")

    cmd = [
        sys.executable,
        str(ULTRAVIOLET_SCRIPT),
        "--project",
        str(project),
        "--year",
        str(year),
        "--max-links",
        str(max_links),
        "--json-output",
        str(report_path),
    ]
    if refresh_owasp:
        cmd.append("--refresh-owasp")

    run_subprocess(cmd, "ultraviolet scan")
    return report_path, load_json(report_path), "generated"


def ensure_cobalt_report(
    project_ref: str,
    provided: str | None,
    *,
    skip_cobalt: bool,
    target: str | None,
    refresh_scans: bool,
    refresh_owasp: bool,
    year: int,
    max_links: int,
    username: str,
    password: str,
    skip_login: bool,
) -> Tuple[Path | None, Dict[str, object] | None, str]:
    if skip_cobalt:
        return None, None, "skipped"

    if provided:
        report_path = Path(provided).resolve()
        return report_path, load_json(report_path), "provided"

    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    slug = normalize_project_slug(project_ref)
    report_path = CACHE_ROOT / f"cobalt_{slug}.json"

    if report_path.exists() and not refresh_scans:
        return report_path, load_json(report_path), "cache"

    if not target:
        return None, None, "missing-target"
    if not COBALT_SCRIPT.exists():
        raise RuntimeError(f"Missing cobalt script: {COBALT_SCRIPT}")

    cmd = [
        sys.executable,
        str(COBALT_SCRIPT),
        "--target",
        target,
        "--year",
        str(year),
        "--max-links",
        str(max_links),
        "--username",
        username,
        "--password",
        password,
        "--json-output",
        str(report_path),
    ]
    if refresh_owasp:
        cmd.append("--refresh-owasp")
    if skip_login:
        cmd.append("--skip-login")

    run_subprocess(cmd, "cobalt scan")
    return report_path, load_json(report_path), "generated"


def extract_findings(report: Dict[str, object] | None) -> List[Dict[str, object]]:
    if not report:
        return []
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return []
    return [item for item in findings if isinstance(item, dict)]


def module_from_endpoint(endpoint: str) -> str | None:
    try:
        path = urllib.parse.urlparse(endpoint).path
    except Exception:
        return None
    match = re.search(r"/vulnerabilities/([a-z0-9_]+)/", path, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).lower()


def looks_like_dvwa(project: Path) -> bool:
    return (project / "vulnerabilities").is_dir() and (
        (project / "dvwa").is_dir() or (project / "login.php").exists()
    )


def infer_dvwa_module_reasons(
    ultraviolet_findings: List[Dict[str, object]],
    cobalt_findings: List[Dict[str, object]],
) -> Dict[str, List[str]]:
    reasons: Dict[str, set[str]] = {}

    def add(module: str, reason: str) -> None:
        if module not in PATCHABLE_DVWA_MODULES:
            return
        reasons.setdefault(module, set()).add(reason)

    for finding in ultraviolet_findings:
        rule_id = str(finding.get("rule_id", "")).strip()
        title = str(finding.get("title", "")).strip()
        rel_file = str(finding.get("file", "")).strip()

        if rule_id in ULTRAVIOLET_RULE_TO_MODULE:
            module = ULTRAVIOLET_RULE_TO_MODULE[rule_id]
            add(module, f"ultraviolet:{rule_id} ({title})")

        module_match = re.search(
            r"(?:^|/)vulnerabilities/([a-z0-9_]+)/", rel_file, flags=re.IGNORECASE
        )
        if module_match:
            module = module_match.group(1).lower()
            add(module, f"ultraviolet:file:{rel_file}")

    for finding in cobalt_findings:
        rule_id = str(finding.get("rule_id", "")).strip()
        title = str(finding.get("title", "")).strip()
        endpoint = str(finding.get("endpoint", "")).strip()

        if rule_id in COBALT_RULE_TO_MODULE:
            module = COBALT_RULE_TO_MODULE[rule_id]
            add(module, f"cobalt:{rule_id} ({title})")

        endpoint_module = module_from_endpoint(endpoint)
        if endpoint_module:
            add(endpoint_module, f"cobalt:endpoint:{endpoint}")

    return {key: sorted(value) for key, value in reasons.items()}


def choose_template_file(target_file: Path) -> Path | None:
    for candidate in ("impossible.php", "high.php", "medium.php"):
        template = target_file.with_name(candidate)
        if template.exists():
            return template
    return None


def propose_dvwa_edits(
    project: Path,
    module_reasons: Dict[str, List[str]],
) -> List[ProposedEdit]:
    edits: List[ProposedEdit] = []

    for module in sorted(module_reasons):
        target_rel = f"vulnerabilities/{module}/source/low.php"
        target = project / target_rel
        if not target.exists():
            continue

        template = choose_template_file(target)
        if template is None:
            continue

        before = target.read_text(encoding="utf-8", errors="ignore")
        after = template.read_text(encoding="utf-8", errors="ignore")
        if before == after:
            continue

        reasons = list(module_reasons[module])
        reasons.append(f"template:{template.relative_to(project).as_posix()}")
        edits.append(
            ProposedEdit(
                relative_path=target_rel,
                strategy="dvwa-template-hardening",
                reasons=reasons,
                before=before,
                after=after,
            )
        )

    return edits


def comment_prefix_for(rel_path: str) -> str | None:
    suffix = Path(rel_path).suffix.lower()
    return COMMENT_STYLE_BY_SUFFIX.get(suffix)


def build_comment(prefix: str, message: str) -> str:
    line = message.strip()
    if prefix == "<!--":
        return f"<!-- {line} -->\n"
    return f"{prefix} {line}\n"


def propose_generic_review_edits(
    project: Path,
    ultraviolet_findings: List[Dict[str, object]],
    already_edited: set[str],
    max_findings: int,
) -> List[ProposedEdit]:
    insertions: Dict[str, List[Tuple[int, str]]] = {}

    count = 0
    for finding in ultraviolet_findings:
        if count >= max_findings:
            break
        rel_file = sanitize_relative_path(str(finding.get("file", "")))
        if not rel_file or rel_file in already_edited:
            continue

        prefix = comment_prefix_for(rel_file)
        if not prefix:
            continue

        file_path = project / rel_file
        if not file_path.exists() or not file_path.is_file():
            continue

        try:
            line_no = int(finding.get("line", 1))
        except (TypeError, ValueError):
            line_no = 1
        line_no = max(1, line_no)

        rule_id = str(finding.get("rule_id", "unknown")).strip() or "unknown"
        title = str(finding.get("title", "Finding")).strip() or "Finding"
        recommendation = str(finding.get("recommendation", "")).strip()
        rec = recommendation[:160].rstrip(".")
        message = f"SECURITY REVIEW {rule_id}: {title}. {rec}".strip()

        insertions.setdefault(rel_file, []).append((line_no, build_comment(prefix, message)))
        count += 1

    edits: List[ProposedEdit] = []
    for rel_file, rows in sorted(insertions.items()):
        file_path = project / rel_file
        before = file_path.read_text(encoding="utf-8", errors="ignore")
        lines = before.splitlines(keepends=True)
        if not lines:
            lines = [""]

        inserted = 0
        for line_no, comment in sorted(rows, key=lambda item: item[0]):
            idx = min(max(line_no - 1 + inserted, 0), len(lines))
            if idx > 0 and comment.strip() in lines[idx - 1]:
                continue
            lines.insert(idx, comment)
            inserted += 1

        after = "".join(lines)
        if before == after:
            continue

        edits.append(
            ProposedEdit(
                relative_path=rel_file,
                strategy="generic-inline-review-comment",
                reasons=["ultraviolet:non-dvwa-safe-comment-fallback"],
                before=before,
                after=after,
            )
        )

    return edits


def render_unified_diff(edits: List[ProposedEdit]) -> str:
    parts: List[str] = []
    for edit in edits:
        diff = difflib.unified_diff(
            edit.before.splitlines(keepends=True),
            edit.after.splitlines(keepends=True),
            fromfile=f"a/{edit.relative_path}",
            tofile=f"b/{edit.relative_path}",
            n=3,
        )
        text = "".join(diff)
        if text:
            if not text.endswith("\n"):
                text += "\n"
            parts.append(text)
    return "".join(parts)


def write_patch_bundle(
    output_dir: Path,
    patch_text: str,
    edits: List[ProposedEdit],
    summary: Dict[str, object],
) -> Tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    patch_path = output_dir / "proposed.patch"
    summary_path = output_dir / "summary.json"

    patch_path.write_text(patch_text, encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    patched_root = output_dir / "patched_files"
    for edit in edits:
        out_file = patched_root / edit.relative_path
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(edit.after, encoding="utf-8")

    return patch_path, summary_path


def apply_edits(project: Path, edits: List[ProposedEdit]) -> None:
    for edit in edits:
        target = project / edit.relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(edit.after, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate review-ready patch bundles for a project under /vorpal_base/context "
            "using ultraviolet and cobalt vulnerability findings."
        )
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Project path under /vorpal_base/context (absolute or relative).",
    )
    parser.add_argument(
        "--ultraviolet-report",
        help="Optional path to existing ultraviolet JSON report.",
    )
    parser.add_argument(
        "--cobalt-report",
        help="Optional path to existing cobalt JSON report.",
    )
    parser.add_argument(
        "--target",
        help="Target URL for running cobalt when cobalt report is missing.",
    )
    parser.add_argument(
        "--skip-cobalt",
        action="store_true",
        help="Skip cobalt ingestion and patch from ultraviolet only.",
    )
    parser.add_argument(
        "--refresh-scans",
        action="store_true",
        help="Force rerun of ultraviolet/cobalt even when cached reports exist.",
    )
    parser.add_argument(
        "--refresh-owasp",
        action="store_true",
        help="Forward OWASP refresh flag when rerunning ultraviolet/cobalt.",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=DEFAULT_YEAR,
        help="OWASP year forwarded to ultraviolet/cobalt (default: 2017).",
    )
    parser.add_argument(
        "--max-links",
        type=int,
        default=DEFAULT_MAX_LINKS,
        help="Max OWASP source links forwarded to ultraviolet/cobalt (default: 3).",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="DVWA username when running cobalt (default: admin).",
    )
    parser.add_argument(
        "--password",
        default="password",
        help="DVWA password when running cobalt (default: password).",
    )
    parser.add_argument(
        "--skip-login",
        action="store_true",
        help="Skip login when running cobalt.",
    )
    parser.add_argument(
        "--max-generic-comments",
        type=int,
        default=20,
        help="Max ultraviolet findings to annotate in generic fallback mode.",
    )
    parser.add_argument(
        "--output-dir",
        help="Optional output directory for patch bundle. Defaults to .patch_project/<project>_<timestamp>.",
    )
    parser.add_argument(
        "--json-output",
        help="Optional explicit path for summary JSON (in addition to bundle summary).",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply generated edits directly to project files.",
    )
    args = parser.parse_args()

    if args.year < 2003 or args.year > 2100:
        print("Year is out of supported range (2003-2100).", file=sys.stderr)
        return 2

    max_links = max(1, min(args.max_links, 5))

    try:
        project, project_ref = resolve_project_path(args.project)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    try:
        uv_path, uv_report, uv_source = ensure_ultraviolet_report(
            project,
            project_ref,
            args.ultraviolet_report,
            refresh_scans=args.refresh_scans,
            refresh_owasp=args.refresh_owasp,
            year=args.year,
            max_links=max_links,
        )
    except Exception as exc:
        print(f"[ERROR] Could not prepare ultraviolet report: {exc}", file=sys.stderr)
        return 1

    try:
        cobalt_path, cobalt_report, cobalt_source = ensure_cobalt_report(
            project_ref,
            args.cobalt_report,
            skip_cobalt=args.skip_cobalt,
            target=args.target,
            refresh_scans=args.refresh_scans,
            refresh_owasp=args.refresh_owasp,
            year=args.year,
            max_links=max_links,
            username=args.username,
            password=args.password,
            skip_login=args.skip_login,
        )
    except Exception as exc:
        print(f"[ERROR] Could not prepare cobalt report: {exc}", file=sys.stderr)
        return 1

    uv_findings = extract_findings(uv_report)
    cobalt_findings = extract_findings(cobalt_report)

    module_reasons: Dict[str, List[str]] = {}
    if looks_like_dvwa(project):
        module_reasons = infer_dvwa_module_reasons(uv_findings, cobalt_findings)

    edits = propose_dvwa_edits(project, module_reasons)
    edited_files = {edit.relative_path for edit in edits}

    if not edits:
        edits.extend(
            propose_generic_review_edits(
                project=project,
                ultraviolet_findings=uv_findings,
                already_edited=edited_files,
                max_findings=max(0, args.max_generic_comments),
            )
        )

    edits = sorted(edits, key=lambda item: item.relative_path)
    patch_text = render_unified_diff(edits)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    default_output_dir = CACHE_ROOT / f"{normalize_project_slug(project_ref)}_{timestamp}"
    output_dir = Path(args.output_dir).resolve() if args.output_dir else default_output_dir

    summary: Dict[str, object] = {
        "project": str(project),
        "reports": {
            "ultraviolet": {"source": uv_source, "path": str(uv_path)},
            "cobalt": {
                "source": cobalt_source,
                "path": str(cobalt_path) if cobalt_path else None,
            },
        },
        "finding_counts": {
            "ultraviolet": len(uv_findings),
            "cobalt": len(cobalt_findings),
        },
        "dvwa_module_reasons": module_reasons,
        "edit_count": len(edits),
        "edits": [
            {
                "relative_path": item.relative_path,
                "strategy": item.strategy,
                "reasons": item.reasons,
                "before_lines": len(item.before.splitlines()),
                "after_lines": len(item.after.splitlines()),
            }
            for item in edits
        ],
    }

    patch_path, summary_path = write_patch_bundle(output_dir, patch_text, edits, summary)

    if args.json_output:
        out = Path(args.json_output).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    if args.apply and edits:
        apply_edits(project, edits)

    print(f"Project: {project}")
    print(f"Ultraviolet report: {uv_source} ({uv_path})")
    if cobalt_path:
        print(f"Cobalt report: {cobalt_source} ({cobalt_path})")
    else:
        print(f"Cobalt report: {cobalt_source}")
    print(f"Findings loaded: ultraviolet={len(uv_findings)}, cobalt={len(cobalt_findings)}")
    print(f"Generated edits: {len(edits)}")
    if module_reasons:
        print("DVWA modules selected:")
        for module in sorted(module_reasons):
            print(f"- {module}: {len(module_reasons[module])} trigger(s)")
    else:
        print("DVWA modules selected: none")

    print(f"Patch bundle: {output_dir}")
    print(f"- Patch: {patch_path}")
    print(f"- Summary: {summary_path}")
    print(f"- Patched snapshots: {output_dir / 'patched_files'}")

    if args.apply:
        print("Apply mode: project files updated.")
    else:
        print("Apply mode: off (project unchanged).")

    if not edits:
        print("No edits were produced from the available findings.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
