#!/usr/bin/env bash
set -euo pipefail

readonly CLONE_BASE_DIR="/vorpal_base/context"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  clone_project.sh <repo-url> [destination] [--branch <name>] [--depth <n>] [--full-history] [--recursive]

Options:
  destination         Optional path under /vorpal_base/context.
  --branch <name>     Checkout a specific branch after clone.
  --depth <n>         Shallow clone depth (default: 1).
  --full-history      Disable shallow clone and fetch full history.
  --recursive         Clone submodules recursively.
  -h, --help          Show this help text.

Destination rules:
  - Omitted destination clones to /vorpal_base/context/<repo-name>
  - Relative destination resolves under /vorpal_base/context
  - Absolute destination must still be inside /vorpal_base/context
EOF
}

die() {
  echo "Error: $*" >&2
  exit 1
}

resolve_git() {
  local bundled_git="${SCRIPT_DIR}/git"
  if [[ -x "${bundled_git}" ]]; then
    printf '%s\n' "${bundled_git}"
    return 0
  fi

  if command -v git >/dev/null 2>&1; then
    command -v git
    return 0
  fi

  if command -v git.exe >/dev/null 2>&1; then
    command -v git.exe
    return 0
  fi

  die "git is not installed or not on PATH."
}

canonicalize_path() {
  local path="$1"
  if command -v realpath >/dev/null 2>&1; then
    realpath -m -- "${path}"
  elif command -v readlink >/dev/null 2>&1; then
    readlink -m -- "${path}"
  else
    printf '%s\n' "${path%/}"
  fi
}

derive_destination() {
  local repo_url="$1"
  local derived="${repo_url%/}"
  derived="${derived##*/}"
  derived="${derived%.git}"
  [[ -n "${derived}" ]] || die "Cannot derive destination from repo URL: ${repo_url}"
  printf '%s\n' "${derived}"
}

resolve_destination() {
  local repo_url="$1"
  local destination_input="$2"

  local clone_root=""
  clone_root="$(canonicalize_path "${CLONE_BASE_DIR}")"

  local destination_path=""
  if [[ -z "${destination_input}" ]]; then
    destination_path="${clone_root}/$(derive_destination "${repo_url}")"
  elif [[ "${destination_input}" = /* ]]; then
    destination_path="$(canonicalize_path "${destination_input}")"
  else
    destination_path="$(canonicalize_path "${clone_root}/${destination_input}")"
  fi

  case "${destination_path}" in
    "${clone_root}"| "${clone_root}/"*) ;;
    *)
      die "Destination must be under ${clone_root}: ${destination_path}"
      ;;
  esac

  printf '%s\n' "${destination_path%/}"
}

ensure_destination_is_safe() {
  local destination="$1"

  [[ ! -e "${destination}" ]] && return 0
  [[ -d "${destination}" ]] || die "Destination exists and is not a directory: ${destination}"

  if [[ -n "$(ls -A "${destination}")" ]]; then
    die "Destination directory exists and is not empty: ${destination}"
  fi
}

main() {
  local repo_url=""
  local destination=""
  local branch=""
  local depth="1"
  local full_history="0"
  local recursive="0"

  while (($# > 0)); do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --branch)
        (($# >= 2)) || die "--branch requires a value."
        branch="$2"
        shift 2
        ;;
      --depth)
        (($# >= 2)) || die "--depth requires a value."
        [[ "$2" =~ ^[1-9][0-9]*$ ]] || die "--depth must be a positive integer."
        depth="$2"
        shift 2
        ;;
      --full-history)
        full_history="1"
        shift
        ;;
      --recursive|--recurse-submodules)
        recursive="1"
        shift
        ;;
      --*)
        die "Unknown option: $1"
        ;;
      *)
        if [[ -z "${repo_url}" ]]; then
          repo_url="$1"
        elif [[ -z "${destination}" ]]; then
          destination="$1"
        else
          die "Too many positional arguments."
        fi
        shift
        ;;
    esac
  done

  [[ -n "${repo_url}" ]] || {
    usage
    die "Missing required <repo-url> argument."
  }

  local git_bin=""
  git_bin="$(resolve_git)"

  destination="$(resolve_destination "${repo_url}" "${destination}")"
  mkdir -p "$(dirname "${destination}")"

  ensure_destination_is_safe "${destination}"

  local cmd=("${git_bin}" clone)

  if [[ "${recursive}" == "1" ]]; then
    cmd+=(--recurse-submodules)
  fi
  if [[ -n "${branch}" ]]; then
    cmd+=(--branch "${branch}")
  fi
  if [[ "${full_history}" != "1" ]]; then
    cmd+=(--depth "${depth}")
  fi

  cmd+=("${repo_url}" "${destination}")

  printf 'Running:'
  printf ' %q' "${cmd[@]}"
  printf '\n'
  "${cmd[@]}"

  echo "Clone complete: ${destination}"
  # WSL/UNC mounts can trigger dubious ownership checks even after a successful clone.
  # Use an ephemeral per-command override only for post-clone verification reads.
  if ! "${git_bin}" -c safe.directory='*' -C "${destination}" remote -v; then
    echo "Warning: clone succeeded, but 'git remote -v' could not be read in this environment."
  fi
}

main "$@"
