# Deployment Notes

This document captures the deployment-specific behavior and workarounds used by the `vorpal-cli-proxy` Docker image.

## Agency Packaging Strategy

- `deployment/build-container.sh` expects a local Agency install at:
  - `~/.config/agency/CurrentVersion/`
- The build passes that directory as a named build context:
  - `--build-context agency=~/.config/agency/CurrentVersion`
- `deployment/Dockerfile` copies it into the image at:
  - `/opt/vorpal/agency`
- The interactive installer path is intentionally disabled in the image:
  - `curl -sSfL https://aka.ms/InstallTool.sh | sh -s agency --use-global-feed`

At runtime (`deployment/start-vorpal-app-server.sh`):

- Agency is copied into the writable home area if needed:
  - `/opt/vorpal/agency` -> `${VORPAL_HOME}/agency`
- `agency` is made executable.
- `${VORPAL_HOME}/agency` is prepended to `PATH`.

This ensures `vorpal`/Codex can launch `agency` MCP commands even in a clean container.

## MCP Config Bootstrapping

- `deployment/codex_config.toml` is baked into:
  - `/vorpal_base/config.toml`
  - `/opt/vorpal/deployment/codex_config.toml`
- Current configured MCP servers include:
  - `ado`
  - `icm`
  - `msft-learn`
  - `security-context`

## Azure CLI Workaround for Agency MCP Auth

### Problem

On native Linux, the Agency Azure auth path can call:

- `az account get-access-token --resource api://...`

For App ID URI scopes (`api://...`), this fails in Azure CLI and leads to false errors like:

- `Azure CLI authentication required. Please run: az login`

### Workaround in Image

The Docker image wraps `/usr/bin/az`:

- real CLI moved to `/usr/bin/az.real`
- wrapper script at `/usr/bin/az`
- wrapper rewrites only this case:
  - `account get-access-token --resource api://...`
  - -> `account get-access-token --scope api://...`

All other `az` commands are passed through unchanged.

### Why this exists

This is a targeted compatibility shim for current Agency behavior on Linux. Remove it once Agency uses `--scope` for `api://...` tokens.

## `/azlogin` + App-Server Restart Flow

The proxy login flow is designed to refresh auth before entering `/cli`:

- `/azlogin` runs:
  - `az login --use-device-code`
- after success, the proxy requests a `vorpal app-server` restart
- restart coordination files:
  - request: `/tmp/vorpal_app_server.restart`
  - ack: `/tmp/vorpal_app_server.restarted`
- `deployment/start-services.sh` handles restart/ack
- proxy waits for backend readiness probe before redirecting to `/cli`

This prevents stale MCP startup from old processes that started before login finished.

## Token Cache Notes

- Container token cache path:
  - `/home/vorpal/.azure`
- You can either:
  - run `/azlogin` inside the container/proxy flow, or
  - map/copy host `~/.azure` into container for warm-start auth

## Build / Run

```bash
./deployment/build-container.sh vorpal-cli-proxy:latest

docker stop vorpal-cli-proxy-latest || true
docker rm vorpal-cli-proxy-latest || true
docker run -d --name vorpal-cli-proxy-latest -p 8000:8000 vorpal-cli-proxy:latest
```

## Quick Verification

Inside container:

```bash
# Verify wrapper exists
ls -l /usr/bin/az /usr/bin/az.real

# Verify scope/resource rewrite path works
az account get-access-token \
  --tenant 72f988bf-86f1-41af-91ab-2d7cd011db47 \
  --resource api://a4a1e66e-9078-4e46-a08f-aab05f5c6f16/access_as_user \
  --query accessToken -o tsv | wc -c

# Probe security-context MCP initialize
printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}\n' \
  | /vorpal_base/agency/agency mcp security-context
```
