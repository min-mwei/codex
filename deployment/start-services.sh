#!/usr/bin/env bash
set -euo pipefail

restart_request_file="${VORPAL_APP_SERVER_RESTART_REQUEST_FILE:-/tmp/vorpal_app_server.restart}"
restart_done_file="${VORPAL_APP_SERVER_RESTART_DONE_FILE:-/tmp/vorpal_app_server.restarted}"
restart_poll_seconds="${VORPAL_APP_SERVER_RESTART_POLL_INTERVAL_SECONDS:-${VORPAL_APP_SERVER_RESTART_POLL_SECONDS:-0.5}}"

app_server_pid=""
proxy_pid=""

mkdir -p "$(dirname "${restart_request_file}")" "$(dirname "${restart_done_file}")"

start_app_server() {
  /opt/vorpal/deployment/start-vorpal-app-server.sh &
  app_server_pid=$!
  printf '%s\n' "${app_server_pid}" > /tmp/vorpal_app_server.pid
}

start_proxy() {
  /opt/vorpal/deployment/start-vorpal-proxy.sh &
  proxy_pid=$!
}

ack_restart() {
  local token="$1"
  if [[ -z "${token}" ]]; then
    return
  fi
  printf '%s\n' "${token}" > "${restart_done_file}"
}

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

start_app_server
printf 'startup:%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${restart_done_file}"
start_proxy

while true; do
  restart_token=""
  if [[ -f "${restart_request_file}" ]]; then
    restart_token="$(cat "${restart_request_file}" 2>/dev/null || true)"
    restart_token="${restart_token//$'\r'/}"
    restart_token="${restart_token%%$'\n'*}"
    rm -f "${restart_request_file}"
  fi

  if ! kill -0 "${proxy_pid}" 2>/dev/null; then
    set +e
    wait "${proxy_pid}" 2>/dev/null
    proxy_exit_code=$?
    set -e
    cleanup
    exit "${proxy_exit_code}"
  fi

  app_server_running=1
  if ! kill -0 "${app_server_pid}" 2>/dev/null; then
    app_server_running=0
  fi

  if [[ -n "${restart_token}" || "${app_server_running}" -eq 0 ]]; then
    if [[ "${app_server_running}" -eq 1 ]]; then
      kill "${app_server_pid}" 2>/dev/null || true
    fi
    wait "${app_server_pid}" 2>/dev/null || true
    start_app_server
    ack_restart "${restart_token}"
  fi

  sleep "${restart_poll_seconds}"
done
