#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
image_tag="${1:-vorpal-cli-proxy:latest}"
vorpal_bin="${repo_root}/codex-rs/target/release/vorpal"
agency_dir="${HOME}/.config/agency/CurrentVersion"

if [[ ! -x "${vorpal_bin}" ]]; then
  echo "Missing prebuilt binary: ${vorpal_bin}" >&2
  echo "Build it first, for example: cargo build --manifest-path codex-rs/Cargo.toml --release -p codex-cli --bin vorpal" >&2
  exit 1
fi

if [[ ! -x "${agency_dir}/agency" ]]; then
  echo "Missing agency executable: ${agency_dir}/agency" >&2
  echo "Install it first, for example: curl -sSfL https://aka.ms/InstallTool.sh | sh -s agency" >&2
  exit 1
fi

docker build \
  --build-context "agency=${agency_dir}" \
  --file "${script_dir}/Dockerfile" \
  --tag "${image_tag}" \
  "${repo_root}"
