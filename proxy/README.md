# Vorpal Proxy

## 1) Start Vorpal CLI App Server (not Codex CLI)

From the repo root, run Vorpal CLI with your Azure OpenAI Responses endpoint:

```bash
VORPAL_HOME=/tmp/vorpal-test \
./vorpal_cli/codex-rs/target/debug/vorpal app-server \
  --listen ws://127.0.0.1:7788 \
  --azureai "https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview"
```

## 2) Start Vorpal Proxy (UI + WebSocket)

From `vorpal_cli/proxy`, install dependencies and start the proxy:

```bash
python3 -m pip install -r requirements.txt
python3 vorpal_proxy.py --listen 127.0.0.1:4501 --target ws://127.0.0.1:7788
```

Then open:

```
http://127.0.0.1:4501
```

The proxy serves the UI on HTTP and forwards WebSocket traffic to the Vorpal CLI app server.

Logs are written to `vorpal_proxy.log` by default.
