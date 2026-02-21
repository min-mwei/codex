#!/usr/bin/env python3
"""Scan a project for OWASP-aligned vulnerability patterns."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple

CONTEXT_ROOT = Path("/vorpal_base/context").resolve()
CACHE_ROOT = CONTEXT_ROOT / ".webapp_vulnerability_scan"
OWASP_SCRIPT_PATH = Path(
    "/vorpal_base/skills/invictus/scripts/scan_owasp_top10.py"
)
OWASP_PROVIDER_NAME = "Invictus"

DEFAULT_YEAR = 2017
DEFAULT_MAX_LINKS = 3
MAX_FILE_SIZE = 1_000_000
MAX_FILES = 12_000
MAX_PRINT_FINDINGS = 200

IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "coverage",
    ".next",
    ".nuxt",
}

SCANNABLE_EXTS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".kt",
    ".kts",
    ".xml",
    ".yml",
    ".yaml",
    ".json",
    ".ini",
    ".conf",
    ".properties",
    ".html",
    ".vue",
    ".svelte",
    ".sql",
    ".sh",
}

SCANNABLE_NAMES = {
    ".env",
    ".env.example",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Jenkinsfile",
}

FALLBACK_2017 = {
    "1": "Injection",
    "2": "Broken Authentication",
    "3": "Sensitive Data Exposure",
    "4": "XML External Entities (XXE)",
    "5": "Broken Access Control",
    "6": "Security Misconfiguration",
    "7": "Cross-Site Scripting (XSS)",
    "8": "Insecure Deserialization",
    "9": "Using Components with Known Vulnerabilities",
    "10": "Insufficient Logging and Monitoring",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}

KNOWN_JS_MIN_MAJOR = {
    "lodash": 4,
    "jquery": 3,
    "axios": 1,
    "express": 4,
    "react": 17,
    "vue": 3,
}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    rank: int
    severity: str
    title: str
    pattern: re.Pattern[str]
    message: str
    recommendation: str


@dataclass
class Finding:
    rule_id: str
    rank: int
    category: str
    severity: str
    title: str
    file: str
    line: int
    evidence: str
    message: str
    recommendation: str


LINE_RULES: List[Rule] = [
    Rule(
        rule_id="inj-shell-true",
        rank=1,
        severity="high",
        title="Shell execution with shell=True",
        pattern=re.compile(
            r"\bsubprocess\.(run|Popen|call|check_output|check_call)\s*\([^#\n]*shell\s*=\s*True"
        ),
        message="Command execution with shell=True can enable injection.",
        recommendation="Avoid shell=True; pass command args as a list and sanitize user input.",
    ),
    Rule(
        rule_id="inj-dynamic-sql",
        rank=1,
        severity="high",
        title="Dynamic SQL construction",
        pattern=re.compile(
            r"\b(SELECT|INSERT|UPDATE|DELETE)\b[^#\n]{0,180}(\+|%s|\.format\(|f\")",
            flags=re.IGNORECASE,
        ),
        message="Dynamic SQL construction often indicates SQL injection risk.",
        recommendation="Use parameterized queries and ORM parameter binding.",
    ),
    Rule(
        rule_id="inj-eval-exec",
        rank=1,
        severity="high",
        title="eval/exec usage",
        pattern=re.compile(r"\b(eval|exec)\s*\("),
        message="Dynamic code execution can lead to injection vulnerabilities.",
        recommendation="Remove eval/exec or strictly sandbox and validate input.",
    ),
    Rule(
        rule_id="auth-hardcoded-secret",
        rank=2,
        severity="high",
        title="Hardcoded credential-like value",
        pattern=re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"
        ),
        message="Hardcoded credential material was detected.",
        recommendation="Move secrets to a secure vault or environment configuration.",
    ),
    Rule(
        rule_id="auth-jwt-none",
        rank=2,
        severity="high",
        title="JWT none algorithm usage",
        pattern=re.compile(r"(?i)\balg(?:orithm)?\b\s*[:=]\s*['\"]none['\"]"),
        message="JWT configured with alg=none bypasses signature integrity.",
        recommendation="Use signed JWT algorithms and validate token signatures.",
    ),
    Rule(
        rule_id="data-verify-false",
        rank=3,
        severity="medium",
        title="TLS verification disabled",
        pattern=re.compile(r"\bverify\s*=\s*False\b"),
        message="TLS certificate verification is disabled.",
        recommendation="Enable TLS certificate verification in all environments.",
    ),
    Rule(
        rule_id="data-weak-hash",
        rank=3,
        severity="medium",
        title="Weak cryptographic hash",
        pattern=re.compile(r"\b(md5|sha1)\s*\(", flags=re.IGNORECASE),
        message="Weak hash algorithms are unsuitable for security-sensitive data.",
        recommendation="Use modern algorithms such as SHA-256, bcrypt, scrypt, or Argon2.",
    ),
    Rule(
        rule_id="data-http-url",
        rank=3,
        severity="low",
        title="Insecure HTTP URL",
        pattern=re.compile(r"(?i)\bhttp://[^\s\"']+"),
        message="Cleartext HTTP endpoint can expose sensitive data in transit.",
        recommendation="Use HTTPS endpoints and enforce TLS.",
    ),
    Rule(
        rule_id="xxe-xml-parser",
        rank=4,
        severity="medium",
        title="Potentially unsafe XML parser usage",
        pattern=re.compile(
            r"(?i)\b(xml\.etree\.ElementTree\.fromstring|lxml\.etree\.fromstring|DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance)\b"
        ),
        message="XML parser usage can allow XXE if secure features are not set.",
        recommendation="Disable external entity resolution and DTD processing.",
    ),
    Rule(
        rule_id="access-admin-route",
        rank=5,
        severity="medium",
        title="Admin route definition",
        pattern=re.compile(
            r"(?i)\b(app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]/admin"
        ),
        message="Admin route detected; ensure authorization is enforced.",
        recommendation="Add explicit authentication and role-based authorization checks.",
    ),
    Rule(
        rule_id="misconfig-debug",
        rank=6,
        severity="medium",
        title="Debug mode enabled",
        pattern=re.compile(
            r"(?i)\b(debug\s*=\s*True|app\.debug\s*=\s*True|NODE_ENV\s*=\s*['\"]development['\"])\b"
        ),
        message="Debug configuration may reveal sensitive internals.",
        recommendation="Disable debug mode in production builds and deployments.",
    ),
    Rule(
        rule_id="misconfig-cors-star",
        rank=6,
        severity="medium",
        title="Permissive CORS configuration",
        pattern=re.compile(
            r"(?i)\b(CORS\([^)]*\*[^)]*\)|Access-Control-Allow-Origin\s*[:=]\s*['\"]\*['\"])\b"
        ),
        message="Wildcard CORS policy can expose APIs to untrusted origins.",
        recommendation="Restrict CORS origins to trusted domains.",
    ),
    Rule(
        rule_id="xss-dom-sink",
        rank=7,
        severity="high",
        title="DOM XSS sink usage",
        pattern=re.compile(
            r"(?i)\b(innerHTML\s*=|outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\()"
        ),
        message="Unsafe DOM sink can lead to cross-site scripting.",
        recommendation="Use safe rendering APIs and sanitize untrusted content.",
    ),
    Rule(
        rule_id="deser-unsafe",
        rank=8,
        severity="high",
        title="Unsafe deserialization API",
        pattern=re.compile(
            r"(?i)\b(pickle\.loads\s*\(|yaml\.load\s*\(|unserialize\s*\(|ObjectInputStream\s*\(|BinaryFormatter)\b"
        ),
        message="Unsafe deserialization can allow remote code execution.",
        recommendation="Use safe deserializers and strict allowlists.",
    ),
    Rule(
        rule_id="monitor-silent-exception",
        rank=10,
        severity="medium",
        title="Silent exception handling",
        pattern=re.compile(
            r"(?i)\b(except\s+[^:\n]+:\s*pass|except:\s*pass|catch\s*\([^\)]*\)\s*\{\s*\})"
        ),
        message="Exceptions are swallowed without logging or alerting.",
        recommendation="Log errors and forward critical events to monitoring.",
    ),
    Rule(
        rule_id="monitor-logging-disabled",
        rank=10,
        severity="medium",
        title="Logging explicitly disabled",
        pattern=re.compile(r"(?i)\b(logging\.disable\s*\(|logger\.disabled\s*=\s*True)\b"),
        message="Logging is explicitly disabled in code paths.",
        recommendation="Keep security-relevant logs enabled and monitored.",
    ),
]


def is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def resolve_project_path(raw_path: str) -> Path:
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
    return project


def parse_owasp_output(output: str) -> Tuple[List[str], Dict[str, str]]:
    links: List[str] = []
    top10: Dict[str, str] = {}

    link_re = re.compile(r"^\d+\.\s+(https?://\S+)$")
    merged_with_conf_re = re.compile(r"^A(10|[1-9]):\s*(.*?)\s+\[[^\]]+\]\s*$")
    merged_plain_re = re.compile(r"^A(10|[1-9]):\s*(.*?)\s*$")

    for raw in output.splitlines():
        line = raw.strip()
        link_match = link_re.match(line)
        if link_match:
            links.append(link_match.group(1))
            continue
        merged_match = merged_with_conf_re.match(line)
        if merged_match:
            rank = merged_match.group(1)
            name = merged_match.group(2).strip()
            top10[rank] = name
            continue
        merged_plain_match = merged_plain_re.match(line)
        if merged_plain_match:
            rank = merged_plain_match.group(1)
            name = merged_plain_match.group(2).strip()
            top10[rank] = name

    return links, top10


def is_valid_cached_owasp_data(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    top10 = data.get("top10")
    if not isinstance(top10, dict):
        return False
    return len(top10) >= 5


def normalize_provider_name(value: object) -> str:
    text = str(value).strip()
    if text.lower() == "invictus":
        return "Invictus"
    return text or OWASP_PROVIDER_NAME


def ensure_owasp_data(
    year: int, max_links: int, refresh: bool
) -> Tuple[Dict[str, object], bool]:
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    cache_path = CACHE_ROOT / f"owasp_top10_{year}.json"

    if cache_path.exists() and not refresh:
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            if is_valid_cached_owasp_data(data):
                provider = data.get("provider")
                if not isinstance(provider, dict):
                    provider = {}
                    data["provider"] = provider
                provider["name"] = normalize_provider_name(
                    provider.get("name", OWASP_PROVIDER_NAME)
                )
                provider.setdefault("script", str(OWASP_SCRIPT_PATH))
                provider["invoked_this_run"] = False
                return data, True
        except Exception:
            pass

    if not OWASP_SCRIPT_PATH.exists():
        raise RuntimeError(
            f"Required script not found: {OWASP_SCRIPT_PATH}. "
            "Install or restore invictus first."
        )

    query = f"owasp vulnerabilities in {year}"
    cmd = [
        sys.executable,
        str(OWASP_SCRIPT_PATH),
        "--query",
        query,
        "--max-links",
        str(max_links),
    ]

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        stderr = proc.stderr.strip() or "(no stderr)"
        raise RuntimeError(
            f"invictus failed (exit {proc.returncode}): {stderr}"
        )

    links, top10 = parse_owasp_output(proc.stdout)
    if year == 2017:
        for rank, name in FALLBACK_2017.items():
            top10.setdefault(rank, name)

    if len(top10) < 5:
        raise RuntimeError(
            "Could not extract enough OWASP Top 10 entries from the helper output."
        )

    data: Dict[str, object] = {
        "query": query,
        "year": year,
        "links": links[:max_links],
        "top10": top10,
        "provider": {
            "name": OWASP_PROVIDER_NAME,
            "script": str(OWASP_SCRIPT_PATH),
            "invoked_this_run": True,
        },
    }
    cache_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return data, False


def should_scan_file(path: Path) -> bool:
    if path.name in SCANNABLE_NAMES:
        return True
    if path.suffix.lower() in SCANNABLE_EXTS:
        return True
    return False


def read_text_file(path: Path) -> str | None:
    with path.open("rb") as handle:
        sample = handle.read(4096)
        if b"\x00" in sample:
            return None
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def get_category_name(top10: Dict[str, str], rank: int) -> str:
    return top10.get(str(rank), FALLBACK_2017.get(str(rank), f"A{rank}"))


def add_finding(
    findings: List[Finding],
    seen: set,
    rule: Rule,
    category: str,
    rel_file: str,
    line_no: int,
    evidence: str,
) -> None:
    dedupe_key = (rule.rule_id, rel_file, line_no, evidence)
    if dedupe_key in seen:
        return
    seen.add(dedupe_key)
    findings.append(
        Finding(
            rule_id=rule.rule_id,
            rank=rule.rank,
            category=category,
            severity=rule.severity,
            title=rule.title,
            file=rel_file,
            line=line_no,
            evidence=evidence,
            message=rule.message,
            recommendation=rule.recommendation,
        )
    )


def scan_lines(
    text: str,
    rel_file: str,
    top10: Dict[str, str],
    findings: List[Finding],
    seen: set,
) -> None:
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        evidence = line[:200]
        for rule in LINE_RULES:
            if rule.pattern.search(line):
                category = get_category_name(top10, rule.rank)
                add_finding(
                    findings=findings,
                    seen=seen,
                    rule=rule,
                    category=category,
                    rel_file=rel_file,
                    line_no=line_no,
                    evidence=evidence,
                )


def parse_major(version: str) -> int | None:
    match = re.search(r"(\d+)", version)
    if not match:
        return None
    return int(match.group(1))


def scan_package_json(
    text: str,
    rel_file: str,
    top10: Dict[str, str],
    findings: List[Finding],
    seen: set,
) -> None:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return

    for section in ("dependencies", "devDependencies"):
        deps = payload.get(section)
        if not isinstance(deps, dict):
            continue
        for pkg, raw_version in deps.items():
            if not isinstance(raw_version, str):
                continue
            version = raw_version.strip()

            if version.lower() in {"latest", "*"} or re.search(r"(^|[^\w])x($|[^\w])", version, flags=re.IGNORECASE):
                rule = Rule(
                    rule_id="dep-unpinned",
                    rank=9,
                    severity="medium",
                    title="Dependency version not pinned",
                    pattern=re.compile("$^"),
                    message="Dependency version is floating and can pull unreviewed updates.",
                    recommendation="Pin dependencies to reviewed versions and run regular audit scans.",
                )
                category = get_category_name(top10, rule.rank)
                add_finding(
                    findings,
                    seen,
                    rule,
                    category,
                    rel_file,
                    1,
                    f"{section}.{pkg}: {version}",
                )

            min_major = KNOWN_JS_MIN_MAJOR.get(pkg.lower())
            current_major = parse_major(version)
            if min_major is not None and current_major is not None and current_major < min_major:
                rule = Rule(
                    rule_id="dep-old-major",
                    rank=9,
                    severity="low",
                    title="Dependency major version appears outdated",
                    pattern=re.compile("$^"),
                    message="Older major versions may contain unpatched known vulnerabilities.",
                    recommendation="Review release notes and upgrade to supported secure versions.",
                )
                category = get_category_name(top10, rule.rank)
                add_finding(
                    findings,
                    seen,
                    rule,
                    category,
                    rel_file,
                    1,
                    f"{section}.{pkg}: {version} (min recommended major {min_major})",
                )


def scan_requirements_txt(
    text: str,
    rel_file: str,
    top10: Dict[str, str],
    findings: List[Finding],
    seen: set,
) -> None:
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r ") or line.startswith("--"):
            continue
        if "==" in line or "@ " in line:
            continue
        package = re.split(r"[<>=!~\s]", line, maxsplit=1)[0].strip()
        if not package:
            continue
        rule = Rule(
            rule_id="dep-unpinned-python",
            rank=9,
            severity="low",
            title="Unpinned Python dependency",
            pattern=re.compile("$^"),
            message="Unpinned dependency can introduce known vulnerable versions unexpectedly.",
            recommendation="Pin exact versions and periodically run vulnerability audits.",
        )
        category = get_category_name(top10, rule.rank)
        add_finding(
            findings,
            seen,
            rule,
            category,
            rel_file,
            line_no,
            line[:200],
        )


def scan_project(project_root: Path, top10: Dict[str, str]) -> Tuple[List[Finding], Dict[str, int]]:
    findings: List[Finding] = []
    seen = set()
    stats = {
        "files_considered": 0,
        "files_scanned": 0,
        "files_skipped_large": 0,
        "files_skipped_binary": 0,
        "files_skipped_filter": 0,
        "files_skipped_error": 0,
    }

    for root, dirs, files in os.walk(project_root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for filename in files:
            if stats["files_considered"] >= MAX_FILES:
                return findings, stats

            stats["files_considered"] += 1
            path = Path(root) / filename

            if not should_scan_file(path):
                stats["files_skipped_filter"] += 1
                continue

            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    stats["files_skipped_large"] += 1
                    continue
            except OSError:
                stats["files_skipped_error"] += 1
                continue

            text = read_text_file(path)
            if text is None:
                stats["files_skipped_binary"] += 1
                continue

            stats["files_scanned"] += 1
            try:
                rel_file = str(path.relative_to(project_root))
            except ValueError:
                rel_file = str(path)

            scan_lines(
                text=text,
                rel_file=rel_file,
                top10=top10,
                findings=findings,
                seen=seen,
            )
            if path.name == "package.json":
                scan_package_json(
                    text=text,
                    rel_file=rel_file,
                    top10=top10,
                    findings=findings,
                    seen=seen,
                )
            elif path.name == "requirements.txt":
                scan_requirements_txt(
                    text=text,
                    rel_file=rel_file,
                    top10=top10,
                    findings=findings,
                    seen=seen,
                )

    return findings, stats


def severity_sort_key(value: str) -> int:
    return SEVERITY_ORDER.get(value.lower(), 99)


def print_report(
    project: Path,
    owasp_data: Dict[str, object],
    from_cache: bool,
    findings: List[Finding],
    stats: Dict[str, int],
) -> None:
    top10 = owasp_data.get("top10", {})
    if not isinstance(top10, dict):
        top10 = {}
    provider = owasp_data.get("provider")
    provider_name = OWASP_PROVIDER_NAME
    provider_script = str(OWASP_SCRIPT_PATH)
    provider_invoked = not from_cache
    if isinstance(provider, dict):
        provider_name = normalize_provider_name(provider.get("name", provider_name))
        provider_script = str(provider.get("script", provider_script))
        raw_invoked = provider.get("invoked_this_run")
        if isinstance(raw_invoked, bool):
            provider_invoked = raw_invoked

    print(f"Project: {project}")
    print(f"OWASP source: {'cache hit' if from_cache else 'refreshed via Invictus'}")
    print(f"OWASP provider: {provider_name} ({provider_script})")
    print(
        "Invictus usage: "
        + (
            "invoked during this scan."
            if provider_invoked
            else "reused cached OWASP data generated by Invictus."
        )
    )
    print(f"OWASP query: {owasp_data.get('query', '(unknown)')}")
    links = owasp_data.get("links", [])
    if isinstance(links, list) and links:
        print("OWASP links:")
        for index, link in enumerate(links, start=1):
            print(f"{index}. {link}")

    print("\nOWASP Top 10 used for mapping:")
    for rank in range(1, 11):
        label = top10.get(str(rank), FALLBACK_2017.get(str(rank), "Unknown"))
        print(f"A{rank}: {label}")

    print("\nScan stats:")
    for key in (
        "files_considered",
        "files_scanned",
        "files_skipped_filter",
        "files_skipped_large",
        "files_skipped_binary",
        "files_skipped_error",
    ):
        print(f"- {key}: {stats.get(key, 0)}")

    if not findings:
        print("\nFindings: none (heuristic scan found no matches).")
        return

    findings_sorted = sorted(
        findings,
        key=lambda f: (f.rank, severity_sort_key(f.severity), f.file, f.line, f.rule_id),
    )

    print(f"\nFindings: {len(findings_sorted)} total")
    printed = 0
    current_rank = None
    for finding in findings_sorted:
        if printed >= MAX_PRINT_FINDINGS:
            remaining = len(findings_sorted) - printed
            print(f"\n... {remaining} additional finding(s) not shown")
            break
        if finding.rank != current_rank:
            current_rank = finding.rank
            print(f"\nA{finding.rank}: {finding.category}")
        print(
            f"- [{finding.severity.upper()}] {finding.title} "
            f"({finding.file}:{finding.line})"
        )
        print(f"  Rule: {finding.rule_id}")
        print(f"  Evidence: {finding.evidence}")
        print(f"  Recommendation: {finding.recommendation}")
        printed += 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a webapp project under /vorpal_base/context using OWASP Top 10 "
            "reference data and heuristic static checks."
        )
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Project path under /vorpal_base/context (absolute or relative).",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=DEFAULT_YEAR,
        help="OWASP year to query via invictus (default: 2017).",
    )
    parser.add_argument(
        "--max-links",
        type=int,
        default=DEFAULT_MAX_LINKS,
        help="How many web search links to read when refreshing OWASP data (default: 3).",
    )
    parser.add_argument(
        "--refresh-owasp",
        action="store_true",
        help="Force refresh OWASP data even if cache exists.",
    )
    parser.add_argument(
        "--json-output",
        help="Optional file path to save a JSON report.",
    )
    args = parser.parse_args()

    if args.year < 2003 or args.year > 2100:
        print("Year is out of supported range (2003-2100).", file=sys.stderr)
        return 2

    try:
        project = resolve_project_path(args.project)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    try:
        owasp_data, from_cache = ensure_owasp_data(
            year=args.year,
            max_links=max(1, min(args.max_links, 5)),
            refresh=args.refresh_owasp,
        )
    except Exception as exc:
        print(f"[ERROR] Could not prepare OWASP data: {exc}", file=sys.stderr)
        return 1

    top10 = owasp_data.get("top10", {})
    if not isinstance(top10, dict):
        print("[ERROR] OWASP cache format is invalid: top10 is missing.", file=sys.stderr)
        return 1

    findings, stats = scan_project(project, top10)
    print_report(project, owasp_data, from_cache, findings, stats)

    if args.json_output:
        provider = owasp_data.get("provider")
        if not isinstance(provider, dict):
            provider = {
                "name": OWASP_PROVIDER_NAME,
                "script": str(OWASP_SCRIPT_PATH),
                "invoked_this_run": not from_cache,
            }
        payload = {
            "project": str(project),
            "owasp_data": owasp_data,
            "owasp_provider": provider,
            "stats": stats,
            "finding_count": len(findings),
            "findings": [asdict(item) for item in findings],
        }
        out_path = Path(args.json_output).resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {out_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
