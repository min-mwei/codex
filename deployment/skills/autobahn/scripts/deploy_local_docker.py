#!/usr/bin/env python3
"""Deploy a project under /vorpal_base/context to local Docker runtime."""

from __future__ import annotations

import argparse
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

CONTEXT_ROOT = Path("/vorpal_base/context").resolve()
DEFAULT_COMPOSE_FILES = (
    "compose.yml",
    "compose.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
)
IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    "__pycache__",
}
MAX_TEXT_FILE_SIZE = 600_000


@dataclass
class BuildHint:
    source_file: Path
    raw_command: str
    dockerfile_hint: str | None
    context_hint: str | None
    tag_hint: str | None


@dataclass
class ComposeHint:
    source_file: Path
    raw_command: str


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


def instruction_file_score(path: Path) -> tuple[int, int, str]:
    name = path.name.lower()
    top_level = 0 if path.parent == path.parents[0] else 1
    if name in {"readme.md", "readme"}:
        return (0, top_level, str(path))
    if "docker" in name:
        return (1, top_level, str(path))
    if "install" in name:
        return (2, top_level, str(path))
    return (3, top_level, str(path))


def collect_instruction_files(project: Path) -> List[Path]:
    found: List[Path] = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        root_path = Path(root)
        for filename in files:
            path = root_path / filename
            lower = filename.lower()
            if lower in {"readme", "readme.md", "readme.txt"}:
                found.append(path)
                continue
            if path.suffix.lower() == ".md":
                if "docker" in lower or "install" in lower or "setup" in lower:
                    found.append(path)
                    continue
                if "docs" in path.parts and len(found) < 40:
                    found.append(path)
    found = sorted(set(found), key=instruction_file_score)
    return found


def normalize_shell_line(line: str) -> str:
    value = line.strip()
    value = re.sub(r"^[`'\"]+", "", value)
    value = re.sub(r"[`'\"]+$", "", value)
    value = re.sub(r"^[#$>]+\s*", "", value)
    return value.strip()


def parse_build_hint_from_line(line: str, source_file: Path) -> BuildHint | None:
    if "docker build" not in line:
        return None
    command = normalize_shell_line(line)
    if "docker build" not in command:
        return None

    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if len(tokens) < 2:
        return None
    if tokens[0] != "docker" or tokens[1] != "build":
        return None

    dockerfile_hint = None
    context_hint = None
    tag_hint = None

    value_options = {
        "-f",
        "--file",
        "-t",
        "--tag",
        "--build-arg",
        "--target",
        "--platform",
        "--network",
        "--label",
        "--cache-from",
        "--cache-to",
        "--secret",
        "--ssh",
    }

    positionals: List[str] = []
    i = 2
    while i < len(tokens):
        token = tokens[i]
        if token in {"-f", "--file"} and i + 1 < len(tokens):
            dockerfile_hint = tokens[i + 1]
            i += 2
            continue
        if token.startswith("--file="):
            dockerfile_hint = token.split("=", 1)[1]
            i += 1
            continue
        if token in {"-t", "--tag"} and i + 1 < len(tokens):
            tag_hint = tokens[i + 1]
            i += 2
            continue
        if token.startswith("--tag="):
            tag_hint = token.split("=", 1)[1]
            i += 1
            continue
        if token in value_options and i + 1 < len(tokens):
            i += 2
            continue
        if token.startswith("-"):
            i += 1
            continue
        positionals.append(token)
        i += 1

    if positionals:
        context_hint = positionals[-1]

    return BuildHint(
        source_file=source_file,
        raw_command=command,
        dockerfile_hint=dockerfile_hint,
        context_hint=context_hint,
        tag_hint=tag_hint,
    )


def extract_build_hints(instruction_files: List[Path]) -> List[BuildHint]:
    hints: List[BuildHint] = []
    for path in instruction_files:
        try:
            if path.stat().st_size > MAX_TEXT_FILE_SIZE:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for raw_line in text.splitlines():
            hint = parse_build_hint_from_line(raw_line, source_file=path)
            if hint:
                hints.append(hint)
    return hints


def extract_compose_hints(instruction_files: List[Path]) -> List[ComposeHint]:
    hints: List[ComposeHint] = []
    compose_re = re.compile(r"\bdocker(?:-|\s+)compose\b.*\bup\b", re.IGNORECASE)
    for path in instruction_files:
        try:
            if path.stat().st_size > MAX_TEXT_FILE_SIZE:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for raw_line in text.splitlines():
            if not compose_re.search(raw_line):
                continue
            command = normalize_shell_line(raw_line)
            hints.append(ComposeHint(source_file=path, raw_command=command))
    return hints


def find_compose_file(project: Path) -> Path | None:
    for filename in DEFAULT_COMPOSE_FILES:
        path = (project / filename).resolve()
        if path.exists() and path.is_file():
            return path
    return None


def resolve_hint_path(
    project: Path, source_file: Path, raw_hint: str | None
) -> Path | None:
    if not raw_hint:
        return None
    hint = raw_hint.strip()
    if not hint:
        return None

    candidate = Path(hint)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        return resolved if resolved.exists() else None

    candidates = [
        (project / candidate).resolve(),
        (source_file.parent / candidate).resolve(),
    ]
    for item in candidates:
        if item.exists():
            return item
    return None


def find_dockerfiles(project: Path) -> List[Path]:
    matches: List[Path] = []
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        root_path = Path(root)
        for filename in files:
            if filename.startswith("Dockerfile"):
                matches.append((root_path / filename).resolve())

    def rank(path: Path) -> tuple[int, int, str]:
        try:
            relative = path.relative_to(project)
            depth = len(relative.parts)
        except ValueError:
            depth = 99
        exact_name = 0 if path.name == "Dockerfile" else 1
        at_root = 0 if path.parent == project else 1
        return (at_root, exact_name, depth, str(path))

    return sorted(matches, key=rank)


def sanitize_name(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", name.strip().lower())
    value = re.sub(r"-{2,}", "-", value).strip("-")
    return value or "webapp"


def run_cmd(
    cmd: List[str], dry_run: bool, cwd: Path | None = None
) -> subprocess.CompletedProcess[str] | None:
    rendered = " ".join(shlex.quote(part) for part in cmd)
    if cwd is not None:
        print(f"$ (cd {shlex.quote(str(cwd))} && {rendered})")
    else:
        print("$ " + rendered)
    if dry_run:
        return None
    run_cwd = str(cwd) if cwd is not None else None
    return subprocess.run(cmd, capture_output=True, text=True, cwd=run_cwd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Deploy a project under /vorpal_base/context using local Docker. "
            "Assumes the project already includes Docker instructions and Dockerfile."
        )
    )
    parser.add_argument(
        "--project",
        required=True,
        help="Project path under /vorpal_base/context (absolute or relative).",
    )
    parser.add_argument(
        "--runtime",
        default="local-docker",
        help="Deployment runtime. Only local-docker is supported.",
    )
    parser.add_argument(
        "--dockerfile",
        help="Optional Dockerfile path (absolute or relative to project).",
    )
    parser.add_argument(
        "--build-context",
        help="Optional docker build context path (absolute or relative to project).",
    )
    parser.add_argument(
        "--image-tag",
        help="Optional image tag. Default: <project-name>:local",
    )
    parser.add_argument(
        "--container-name",
        help="Optional container name. Default: <project-name>-local",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="Build image only. Do not run container.",
    )
    parser.add_argument(
        "--no-replace",
        action="store_true",
        help="Fail if container with target name exists.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print commands without executing them.",
    )
    parser.add_argument(
        "--force-dockerfile",
        action="store_true",
        help="Ignore compose hints/files and force Dockerfile build+run mode.",
    )
    args = parser.parse_args()

    if args.runtime != "local-docker":
        print(
            "[ERROR] Unsupported runtime. Only 'local-docker' is supported.",
            file=sys.stderr,
        )
        return 2

    if shutil.which("docker") is None:
        print("[ERROR] Docker is not installed or not on PATH.", file=sys.stderr)
        return 1

    try:
        project = resolve_project_path(args.project)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    instruction_files = collect_instruction_files(project)
    build_hints = extract_build_hints(instruction_files)
    primary_hint = build_hints[0] if build_hints else None
    compose_hints = extract_compose_hints(instruction_files)
    primary_compose_hint = compose_hints[0] if compose_hints else None
    compose_file = find_compose_file(project)

    use_compose = (
        compose_file is not None
        and primary_compose_hint is not None
        and not args.force_dockerfile
        and not args.dockerfile
        and not args.build_context
    )

    if use_compose:
        print(f"Project: {project}")
        print("Runtime: local-docker")
        print("Deployment mode: docker-compose")
        print(f"Instruction files scanned: {len(instruction_files)}")
        print(f"Compose instruction source: {primary_compose_hint.source_file}")
        print(f"Compose instruction command: {primary_compose_hint.raw_command}")
        print(f"Compose file: {compose_file}")

        if args.image_tag or args.container_name:
            print(
                "Note: --image-tag/--container-name are ignored in compose mode.",
                file=sys.stderr,
            )
        if args.no_replace:
            print("Note: --no-replace has no effect in compose mode.", file=sys.stderr)

        compose_base = ["docker", "compose", "-f", str(compose_file)]
        if args.build_only:
            compose_cmd = compose_base + ["build"]
        else:
            compose_cmd = compose_base + ["up", "-d"]

        compose_proc = run_cmd(compose_cmd, dry_run=args.dry_run, cwd=project)
        if compose_proc is not None and compose_proc.returncode != 0:
            print(compose_proc.stdout, end="")
            print(compose_proc.stderr, end="", file=sys.stderr)
            print("[ERROR] Docker compose command failed.", file=sys.stderr)
            return compose_proc.returncode or 1
        if compose_proc is not None and compose_proc.stdout.strip():
            print(compose_proc.stdout.strip())

        if args.dry_run:
            print("Dry run complete.")
            return 0

        ps_cmd = compose_base + ["ps"]
        ps_proc = subprocess.run(ps_cmd, capture_output=True, text=True, cwd=str(project))
        if ps_proc.returncode == 0 and ps_proc.stdout.strip():
            print("Compose services:")
            print(ps_proc.stdout.strip())
        return 0

    dockerfile_path: Path | None = None
    if args.dockerfile:
        dockerfile_path = resolve_hint_path(project, project, args.dockerfile)
        if dockerfile_path is None:
            print(
                f"[ERROR] --dockerfile path not found: {args.dockerfile}",
                file=sys.stderr,
            )
            return 2
    elif primary_hint and primary_hint.dockerfile_hint:
        dockerfile_path = resolve_hint_path(
            project, primary_hint.source_file, primary_hint.dockerfile_hint
        )

    if dockerfile_path is None:
        dockerfiles = find_dockerfiles(project)
        if not dockerfiles:
            print(
                "[ERROR] No Dockerfile found in project. "
                "This simple skill requires Docker instructions/Dockerfile.",
                file=sys.stderr,
            )
            return 1
        dockerfile_path = dockerfiles[0]

    dockerfile_path = dockerfile_path.resolve()
    if not is_within(dockerfile_path, project):
        print(
            f"[ERROR] Dockerfile must be inside project directory. Got: {dockerfile_path}",
            file=sys.stderr,
        )
        return 2

    build_context: Path | None = None
    if args.build_context:
        build_context = resolve_hint_path(project, project, args.build_context)
        if build_context is None:
            print(
                f"[ERROR] --build-context path not found: {args.build_context}",
                file=sys.stderr,
            )
            return 2
    elif primary_hint and primary_hint.context_hint:
        build_context = resolve_hint_path(
            project, primary_hint.source_file, primary_hint.context_hint
        )

    if build_context is None:
        build_context = project if dockerfile_path.parent == project else dockerfile_path.parent

    build_context = build_context.resolve()
    if not is_within(build_context, project):
        print(
            f"[ERROR] Build context must be inside project directory. Got: {build_context}",
            file=sys.stderr,
        )
        return 2

    image_tag = (
        args.image_tag
        or (primary_hint.tag_hint if primary_hint and primary_hint.tag_hint else None)
        or f"{sanitize_name(project.name)}:local"
    )
    container_name = args.container_name or f"{sanitize_name(project.name)}-local"

    print(f"Project: {project}")
    print("Runtime: local-docker")
    print(f"Instruction files scanned: {len(instruction_files)}")
    if primary_hint:
        print(f"Build instruction source: {primary_hint.source_file}")
        print(f"Build instruction command: {primary_hint.raw_command}")
    print(f"Dockerfile: {dockerfile_path}")
    print(f"Build context: {build_context}")
    print(f"Image tag: {image_tag}")
    print(f"Container name: {container_name}")

    build_cmd = [
        "docker",
        "build",
        "-f",
        str(dockerfile_path),
        "-t",
        image_tag,
        str(build_context),
    ]
    build_proc = run_cmd(build_cmd, dry_run=args.dry_run)
    if build_proc is not None and build_proc.returncode != 0:
        print(build_proc.stdout, end="")
        print(build_proc.stderr, end="", file=sys.stderr)
        print("[ERROR] Docker build failed.", file=sys.stderr)
        return build_proc.returncode or 1
    if build_proc is not None and build_proc.stdout.strip():
        print(build_proc.stdout.strip())

    if args.build_only:
        print("Build completed (build-only mode).")
        return 0

    if not args.no_replace:
        rm_cmd = ["docker", "rm", "-f", container_name]
        rm_proc = run_cmd(rm_cmd, dry_run=args.dry_run)
        if rm_proc is not None and rm_proc.returncode == 0 and rm_proc.stdout.strip():
            print(rm_proc.stdout.strip())

    run_cmdline = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-P",
        image_tag,
    ]
    run_proc = run_cmd(run_cmdline, dry_run=args.dry_run)
    if run_proc is not None and run_proc.returncode != 0:
        print(run_proc.stdout, end="")
        print(run_proc.stderr, end="", file=sys.stderr)
        print("[ERROR] Docker run failed.", file=sys.stderr)
        return run_proc.returncode or 1

    if run_proc is None:
        print("Dry run complete.")
        return 0

    container_id = run_proc.stdout.strip()
    print(f"Container started: {container_id}")

    port_cmd = ["docker", "port", container_name]
    port_proc = subprocess.run(port_cmd, capture_output=True, text=True)
    if port_proc.returncode == 0 and port_proc.stdout.strip():
        print("Published ports:")
        print(port_proc.stdout.strip())
    else:
        print("No published ports reported by Docker.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
