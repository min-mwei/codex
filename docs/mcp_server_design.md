# Codex MCP Server Design

This document captures the architecture of the `codex_mcp_server` crate so
future integrations have a single reference point for both the runtime design
and the supporting code structure.

## High-Level Goals

* Offer a single executable (`codex mcp-server`) that can run over **stdio** or
  an **HTTP + SSE transport**.
* Provide **multi-session** handling on the HTTP transport so every MCP client
  receives isolated state.
* Forward MCP tool calls to both the local Codex engine *and* **remote MCP
  servers** that may be configured in `config.toml`.
* Support **Azure Entra ID** authentication for Streamable HTTP transports and
  allow remote servers to supply bearer tokens via environment variables.
* Record structured tracing to both stderr and a persistent log file with
  sensitive data (e.g., bearer tokens) redacted.
* Expose MCP functionality through the main `codex` CLI so users can run
  `codex mcp-server --port ...` without compiling a separate binary.

## Key Components

| File | Responsibility |
| --- | --- |
| `codex-rs/mcp-server/src/lib.rs` | Entry points for stdio and HTTP transports, session lifecycle, tracing initialisation. |
| `codex-rs/mcp-server/src/message_processor.rs` | JSON-RPC request handling, Codex session management, remote MCP forwarding. |
| `codex-rs/mcp-server/src/codex_tool_runner.rs` | Bridges Codex conversations with MCP tool results, including exec/patch approvals. |
| `codex-rs/mcp-server/src/session_log.rs` | Session-scoped logging macros. |
| `codex-rs/mcp-server/src/redact.rs` | Redaction helper for logging sensitive data. |
| `codex-rs/core/src/mcp_connection_manager.rs` | Remote MCP wiring (stdio, streamable HTTP, Azure tokens). |
| `codex-rs/core/src/model_provider_info.rs` | Azure default credential support for model providers. |
| `codex-rs/core/src/azure_auth.rs` | Wrapper around `azure_identity::DefaultAzureCredential`. |
| `codex-rs/cli/src/main.rs` | CLI integration of `codex mcp-server --port/--host`. |

### Transport Modes

* **Stdio**: `run_main` ties together async tasks for stdin, message processing,
  stdout, and Ctrl-C handling.
* **HTTP/SSE**: `run_http_server` (Axum) maintains a `HttpMultiState` with one
  `SessionState` (channels, SSE broadcast) per session. The `ensure_session`
  helper spawns message processors on demand.

### Remote MCP Forwarding

* `McpConnectionManager::new` loads StdIO and Streamable HTTP servers from the
  config, applying enabled/disabled tool filters.
* Streamable HTTP transports call `resolve_bearer_token`, which:
  * honours `bearer_token_env_var`, and
  * falls back to Azure default credentials when the URL host matches known AOAI
    patterns (`azure_auth::host_supports_default_credential`).
* `MessageProcessor::handle_call_tool` routes calls recognised as remote tools
  and converts errors to user-friendly `CallToolResult`s.

### Approvals and Session Logging

* `codex_tool_runner.rs` reacts to approval/patch events emitted by Codex and
  forwards them to the client via `ElicitRequest` messages.
* `session_log.rs` macros keep `session_id` consistently recorded across logs.

### CLI Integration

* The `codex` binary now exposes `codex mcp-server --port <PORT> [--host <HOST>]`
  via the new `McpServerArgs`, allowing users to choose HTTP or stdio transports
  with a single command.
* Running without `--port` retains stdio mode for backwards compatibility.

## Validation – `mcp_server_test`

A new unit test named `mcp_server_test` was added inside
`codex-rs/cli/src/main.rs`. The test verifies that `MultitoolCli` accepts the
`--port`/`--host` flags and routes them into the `McpServer` subcommand without
invoking the server runtime. This ensures the CLI surface stays in sync with the
transport code as future changes are integrated.

Complementary tests that were already ported:

* `codex-rs/mcp-server/tests` exercise end-to-end Codex sessions, approval
  flows, and error paths.
* Existing CLI integration tests (`mcp_add_remove.rs`, `mcp_list.rs`) continue
  to validate remote MCP management commands.

To run the new and existing validations:

```bash
cargo test -p codex-cli -- mcp_server_test
cargo test -p codex-cli
cargo test -p codex-mcp-server
```

## Integration Notes

* The Azure authentication support pulls in `azure_core` and `azure_identity`
  which now live in the workspace `Cargo.toml` and
  `core/Cargo.toml`.
* The `codex_mcp_server` crate depends on Axum HTTP/SSE helpers plus tracing
  appender; the CLI crate in turn depends on the server.
* Whenever remote MCP logic changes upstream, revisit:
  * `azure_auth.rs` and `resolve_bearer_token` for authentication tweaks.
  * The session-handling code in `lib.rs` (ensuring SSE + HTTP remain stable).
  * The CLI tests (`mcp_server_test`) so the user interface remains validated.

Please update this document whenever the transport surface, authentication, or
CLI ergonomics change so downstream integrations remain in sync with the current
`codex_mcp_server` implementation.
