#!/usr/bin/env bash
set -euo pipefail

readonly CLONE_BASE_DIR="/vorpal_base/context"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage:
  clone_project.sh <repo-url> [destination] [--branch <name>] [--depth <n>] [--full-history] [--recursive] [--ado-az-login] [--ado-resource <id-or-uri>]

Options:
  destination         Optional path under /vorpal_base/context.
  --branch <name>     Checkout a specific branch after clone.
  --depth <n>         Shallow clone depth (default: 1).
  --full-history      Disable shallow clone and fetch full history.
  --recursive         Clone submodules recursively.
  --ado-az-login      Require Azure CLI login context to get an ADO bearer token.
  --ado-resource <v>  Token resource for Azure CLI (default: Azure DevOps app id).
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
  local ado_az_login="0"
  local ado_resource="499b84ac-1321-427f-aa17-267ca6975798"
  local ado_access_token=""
  local ado_auto_auth="0"

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
      --ado-az-login)
        ado_az_login="1"
        shift
        ;;
      --ado-resource)
        (($# >= 2)) || die "--ado-resource requires a value."
        ado_resource="$2"
        shift 2
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

  case "${repo_url}" in
    https://dev.azure.com/*|http://dev.azure.com/*|https://*.visualstudio.com/*|http://*.visualstudio.com/*)
      ado_auto_auth="1"
      ;;
  esac

  local git_bin=""
  git_bin="$(resolve_git)"

  if [[ "${ado_az_login}" == "1" || "${ado_auto_auth}" == "1" ]]; then
    if ! command -v az >/dev/null 2>&1; then
      if [[ "${ado_az_login}" == "1" ]]; then
        die "Azure CLI (az) is not installed or not on PATH."
      fi
      echo "Info: Azure CLI not found; continuing without injected ADO bearer token." >&2
    else
      if ado_access_token="$(az account get-access-token --resource "${ado_resource}" --query accessToken -o tsv 2>/dev/null)" && [[ -n "${ado_access_token}" ]]; then
        :
      elif [[ "${ado_az_login}" == "1" ]]; then
        die "Azure CLI token acquisition failed. Run 'az login' and try again."
      else
        echo "Info: Azure CLI token unavailable; continuing without injected ADO bearer token. For private ADO repos, run 'az login' and pass --ado-az-login." >&2
      fi
    fi
  fi

  destination="$(resolve_destination "${repo_url}" "${destination}")"
  mkdir -p "$(dirname "${destination}")"

  ensure_destination_is_safe "${destination}"

  local cmd=("${git_bin}")
  if [[ -n "${ado_access_token}" ]]; then
    cmd+=(-c "http.extraheader=AUTHORIZATION: bearer ${ado_access_token}")
  fi
  cmd+=(clone)

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

  local display_cmd=("${cmd[@]}")
  if [[ -n "${ado_access_token}" ]]; then
    for i in "${!display_cmd[@]}"; do
      if [[ "${display_cmd[$i]}" == "http.extraheader=AUTHORIZATION: bearer "* ]]; then
        display_cmd[$i]="http.extraheader=AUTHORIZATION: bearer ***"
      fi
    done
  fi

  printf 'Running:'
  printf ' %q' "${display_cmd[@]}"
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
