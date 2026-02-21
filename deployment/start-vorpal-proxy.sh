#!/usr/bin/env bash
set -euo pipefail

target_url="${VORPAL_PROXY_TARGET:-ws://127.0.0.1:7788}"
listen_addr="${VORPAL_PROXY_LISTEN:-0.0.0.0:8000}"
log_file="${VORPAL_PROXY_LOG_FILE:-/var/log/vorpal/vorpal_proxy.log}"

mkdir -p "$(dirname "${log_file}")"

exec /usr/bin/python3.13 -m vorpal_proxy \
  --target "${target_url}" \
  --listen "${listen_addr}" \
  --log-file "${log_file}"
