#!/usr/bin/env bash
set -euo pipefail

export VORPAL_HOME="${VORPAL_HOME:-/vorpal_base}"
listen_addr="${VORPAL_APP_SERVER_LISTEN:-ws://127.0.0.1:7788}"
azure_endpoint="${VORPAL_AZUREAI_ENDPOINT:-https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview}"
agency_source_dir="/opt/vorpal/agency"
agency_target_dir="${VORPAL_HOME}/agency"
config_template="/opt/vorpal/deployment/codex_config.toml"
config_path="${VORPAL_HOME}/config.toml"

mkdir -p "${VORPAL_HOME}"

if [[ ! -d "${agency_target_dir}" ]]; then
  cp -a "${agency_source_dir}" "${agency_target_dir}"
fi
chmod +x "${agency_target_dir}/agency"

if [[ ! -f "${config_path}" ]]; then
  cp "${config_template}" "${config_path}"
fi

export PATH="${agency_target_dir}:${PATH}"

exec /usr/local/bin/vorpal \
  -s danger-full-access \
  --dangerously-bypass-approvals-and-sandbox \
  app-server \
  --listen "${listen_addr}" \
  --azureai "${azure_endpoint}"
