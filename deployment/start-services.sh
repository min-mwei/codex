#!/usr/bin/env bash
set -euo pipefail

/opt/vorpal/deployment/start-vorpal-app-server.sh &
app_server_pid=$!

/opt/vorpal/deployment/start-vorpal-proxy.sh &
proxy_pid=$!

cleanup() {
  if kill -0 "${proxy_pid}" 2>/dev/null; then
    kill "${proxy_pid}" 2>/dev/null || true
  fi
  if kill -0 "${app_server_pid}" 2>/dev/null; then
    kill "${app_server_pid}" 2>/dev/null || true
  fi
  wait "${proxy_pid}" "${app_server_pid}" 2>/dev/null || true
}

trap cleanup INT TERM

wait -n "${app_server_pid}" "${proxy_pid}"
exit_code=$?
cleanup
exit "${exit_code}"
