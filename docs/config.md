# Configuration

For basic configuration instructions, see [this documentation](https://developers.openai.com/codex/config-basic).

For advanced configuration instructions, see [this documentation](https://developers.openai.com/codex/config-advanced).

For a full configuration reference, see [this documentation](https://developers.openai.com/codex/config-reference).

## Azure OpenAI (Entra)

You can configure a custom model provider that targets a full Azure Responses endpoint
and authenticates with Entra (Azure AD):

```toml
[model_providers.azure-entra]
name = "Azure OpenAI (Entra)"
endpoint = "https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview"
azure_entra_auth = true
wire_api = "responses"
supports_websockets = false
```

Then select it with:

```toml
model_provider = "azure-entra"
```

Authentication behavior:
- If `AZURE_OPENAI_ENTRA_TOKEN` is set, Codex uses that bearer token.
- Otherwise Codex runs `az account get-access-token --scope https://cognitiveservices.azure.com/.default --query accessToken --output tsv`.

### Azure via CLI flag

You can also set Azure provider defaults directly from the command line:

```bash
vorpal --azureai "https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview"
```

To isolate config/auth/session files per environment, set `VORPAL_HOME`:

```bash
VORPAL_HOME=/tmp/vorpal-test vorpal --azureai "https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview"
```

This applies the following runtime overrides:
- `model_provider = "azureai"`
- `model = "gpt-5.2-codex"`
- `model_providers.azureai.endpoint = <URL>`
- `model_providers.azureai.azure_entra_auth = true`
- `model_providers.azureai.wire_api = "responses"`
- `model_providers.azureai.supports_websockets = true`

## Connecting to MCP servers

Codex can connect to MCP servers configured in `~/.codex/config.toml`. See the configuration reference for the latest MCP server options:

- https://developers.openai.com/codex/config-reference

## Apps (Connectors)

Use `$` in the composer to insert a ChatGPT connector; the popover lists accessible
apps. The `/apps` command lists available and installed apps. Connected apps appear first
and are labeled as connected; others are marked as can be installed.

## Notify

Codex can run a notification hook when the agent finishes a turn. See the configuration reference for the latest notification settings:

- https://developers.openai.com/codex/config-reference

## JSON Schema

The generated JSON Schema for `config.toml` lives at `codex-rs/core/config.schema.json`.

## Notices

Codex stores "do not show again" flags for some UI prompts under the `[notice]` table.

Ctrl+C/Ctrl+D quitting uses a ~1 second double-press hint (`ctrl + c again to quit`).
