#!/usr/bin/env bash
set -euo pipefail

export VORPAL_HOME="${VORPAL_HOME:-/vorpal_base}"
listen_addr="${VORPAL_APP_SERVER_LISTEN:-ws://127.0.0.1:7788}"
azure_endpoint="${VORPAL_AZUREAI_ENDPOINT:-https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview}"

mkdir -p "${VORPAL_HOME}"

exec /usr/local/bin/vorpal \
  -s danger-full-access \
  --dangerously-bypass-approvals-and-sandbox \
  app-server \
  --listen "${listen_addr}" \
  --azureai "${azure_endpoint}"
