# Vorpal Proxy

FastAPI + WebSocket proxy for Vorpal app-server.

## 1) Start Vorpal CLI App Server

From the repo root:

```bash
VORPAL_HOME=/tmp/vorpal-test \
./codex-rs/target/debug/vorpal app-server \
  --listen ws://127.0.0.1:7788 \
  --azureai "https://<your-azure-endpoint>/openai/responses?api-version=2025-04-01-preview"
```

## 2) Install Proxy Package

From the repo root:

```bash
python3 -m pip install -e ./proxy
```

## 3) Launch With Uvicorn Directly

From the repo root:

```bash
VORPAL_PROXY_TARGET=ws://127.0.0.1:7788 \
VORPAL_PROXY_LOG_FILE=vorpal_proxy.log \
uvicorn --factory vorpal_proxy.app:create_app --host 127.0.0.1 --port 4501
```

Open:

```text
http://127.0.0.1:4501
```

## 4) Launch With Installed CLI

After `pip install -e ./proxy`:

```bash
vorpal-proxy \
  --target ws://127.0.0.1:7788 \
  --listen 127.0.0.1:4501
```

## Environment Variables

- `VORPAL_PROXY_TARGET` default: `ws://127.0.0.1:4500`
- `VORPAL_PROXY_LOG_FILE` default: `vorpal_proxy.log`
- `VORPAL_APP_SERVER_RESTART_REQUEST_FILE` default: `/tmp/vorpal_app_server.restart`
- `VORPAL_APP_SERVER_RESTART_DONE_FILE` default: `/tmp/vorpal_app_server.restarted`
- `VORPAL_APP_SERVER_RESTART_TIMEOUT_SECONDS` default: `45`
- `VORPAL_APP_SERVER_RESTART_POLL_INTERVAL_SECONDS` default: `0.5`

`vorpal.html` is bundled in the package (`vorpal_proxy/vorpal.html`) and served at `/` and `/vorpal.html`.
The proxy serves the UI over HTTP and bridges WebSocket traffic to the configured backend.
