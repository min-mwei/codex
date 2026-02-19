# Vorpal CLI Integration Design Notes

This document tracks the fork-specific design points for the Vorpal CLI so we can repeatedly merge upstream Codex changes without losing Vorpal behavior.

## Scope

The authoritative upstream codebase is in `vorpal_cli/` (especially `vorpal_cli/codex-rs/`).

This file focuses on the user-facing CLI fork behavior:
- command naming (`vorpal` vs `codex`)
- home directory environment variable semantics (`VORPAL_HOME`)
- Azure OpenAI convenience wiring (`--azureai`)
- TUI branding text (`Vorpal` banner/welcome)
- compatibility rules we intentionally keep to reduce merge pain

## 1. Canonical CLI Identity

Vorpal is the canonical executable name.

Design points:
- Primary binary target is `vorpal`.
- Help/usage should display `vorpal`, not `codex`.
- Shell completion should generate for `vorpal`.
- User-facing command hints should say `vorpal ...`.

Current implementation:
- `vorpal_cli/codex-rs/cli/Cargo.toml`
  - `[[bin]] name = "vorpal"`
- `vorpal_cli/codex-rs/cli/src/main.rs`
  - clap `bin_name = "vorpal"`
  - clap `override_usage = "vorpal ..."`
  - completion generator command name is `vorpal`
  - resume hints rewrite `codex ...` -> `vorpal ...`
- `vorpal_cli/codex-rs/cli/src/mcp_cmd.rs`
  - MCP examples/hints use `vorpal mcp ...`

Compatibility note:
- Internal crate names remain `codex-*` to minimize upstream drift.
- Some internal metadata strings may still include "codex"; these are not user command entrypoints.

## 2. Home Directory Env Variable Policy

Vorpal-specific home override is `VORPAL_HOME`.

Resolution order:
1. `VORPAL_HOME` (primary)
2. `CODEX_HOME` (legacy fallback)
3. `~/.codex` (default)

Validation behavior:
- If env var is set, path must exist and be a directory.
- Path is canonicalized.
- Invalid or missing path is an error.

Current implementation:
- `vorpal_cli/codex-rs/utils/home-dir/src/lib.rs`

Design intent:
- Make Vorpal naming first-class (`VORPAL_HOME`).
- Keep `CODEX_HOME` compatibility for existing scripts and environments.
- Keep `~/.codex` default to avoid disruptive data migration during upstream sync.

## 3. Azure OpenAI Convenience Flag (`--azureai`)

Vorpal supports a top-level convenience flag:
- `--azureai <Responses endpoint URL>`

Behavior:
- Automatically selects provider `azureai`.
- Automatically enables Entra auth defaults.
- Forces Responses API wiring.
- Enables websocket support by default.
- Sets default model to `gpt-5.2-codex`.

Applied overrides:
- `model_provider = "azureai"`
- `model = "gpt-5.2-codex"`
- `model_providers.azureai.name = "Azure OpenAI (Entra)"`
- `model_providers.azureai.endpoint = <URL>`
- `model_providers.azureai.azure_entra_auth = true`
- `model_providers.azureai.wire_api = "responses"`
- `model_providers.azureai.supports_websockets = true`

Precedence rule:
- Explicit `-c key=value` flags remain higher precedence than the injected `--azureai` defaults.

Propagation rule:
- Root-level `--azureai` overrides propagate through interactive and subcommand flows.

Current implementation:
- `vorpal_cli/codex-rs/cli/src/main.rs`
- `vorpal_cli/docs/config.md`

## 3b. TUI Branding

Vorpal branding is shown in startup/session UI header text.

Design points:
- Session/status header title should render `>_ Vorpal (vX)`.
- Onboarding welcome line should say `Welcome to Vorpal`.
- Snapshot fixtures should assert `Vorpal` in status header output.

Current implementation:
- `vorpal_cli/codex-rs/tui/src/history_cell.rs`
- `vorpal_cli/codex-rs/tui/src/status/card.rs`
- `vorpal_cli/codex-rs/tui/src/onboarding/welcome.rs`
- `vorpal_cli/codex-rs/tui/src/status/snapshots/*.snap`

## 4. Test Expectations in Vorpal Fork

CLI tests should target Vorpal entrypoints and env semantics.

Current test adjustments:
- `cargo_bin("vorpal")` instead of `cargo_bin("codex")`
- `VORPAL_HOME` in test environment setup
- output assertions expecting `vorpal ...` hints

Current files:
- `vorpal_cli/codex-rs/cli/tests/features.rs`
- `vorpal_cli/codex-rs/cli/tests/mcp_add_remove.rs`
- `vorpal_cli/codex-rs/cli/tests/mcp_list.rs`
- `vorpal_cli/codex-rs/cli/tests/execpolicy.rs`

## 5. Upstream Merge Checklist (Codex-Centric -> Vorpal)

When pulling upstream Codex changes, re-validate these fork invariants:

1. CLI naming
- Ensure top-level clap `bin_name` and usage remain `vorpal`.
- Ensure completion command name remains `vorpal`.
- Ensure user command hints remain `vorpal ...`.

2. Home env semantics
- Preserve `VORPAL_HOME` as primary env var.
- Preserve `CODEX_HOME` fallback behavior.
- Preserve validation + canonicalization behavior.

3. Azure convenience behavior
- Preserve `--azureai` flag existence.
- Preserve default model `gpt-5.2-codex`.
- Preserve override precedence (`-c` wins).

4. TUI branding
- Keep header label as `Vorpal` (not `OpenAI Codex`) in session/status cards.
- Keep onboarding welcome text as `Welcome to Vorpal`.

5. Tests
- Keep CLI tests using `cargo_bin("vorpal")`.
- Keep tests using `VORPAL_HOME`.

6. Docs
- Keep command examples using `vorpal`.
- Keep `VORPAL_HOME` examples.

## 6. Current Change Inventory

These are the concrete files that currently carry Vorpal-specific deltas:

- `vorpal_cli/codex-rs/cli/Cargo.toml`
  - CLI binary target renamed to `vorpal`.
- `vorpal_cli/codex-rs/cli/src/main.rs`
  - CLI branding changed to `vorpal` in usage/help.
  - completion generation uses `vorpal`.
  - resume output hints emit `vorpal resume ...`.
  - `--azureai` global flag wiring and injected defaults.
  - default Azure model forced to `gpt-5.2-codex`.
- `vorpal_cli/codex-rs/cli/src/mcp_cmd.rs`
  - MCP usage/help/status hints changed from `codex ...` to `vorpal ...`.
  - home resolution error text mentions `VORPAL_HOME/CODEX_HOME`.
- `vorpal_cli/codex-rs/utils/home-dir/src/lib.rs`
  - home directory lookup precedence changed to `VORPAL_HOME` first, then legacy `CODEX_HOME`.
  - tests added/updated for precedence and fallback behavior.
- `vorpal_cli/codex-rs/cli/tests/features.rs`
  - uses `cargo_bin("vorpal")` and `VORPAL_HOME`.
- `vorpal_cli/codex-rs/cli/tests/mcp_add_remove.rs`
  - uses `cargo_bin("vorpal")` and `VORPAL_HOME`.
- `vorpal_cli/codex-rs/cli/tests/mcp_list.rs`
  - uses `cargo_bin("vorpal")` and `VORPAL_HOME`.
  - expected hint text updated to `vorpal mcp remove ...`.
- `vorpal_cli/codex-rs/cli/tests/execpolicy.rs`
  - uses `cargo_bin("vorpal")` and `VORPAL_HOME`.
- `vorpal_cli/codex-rs/tui/src/history_cell.rs`
  - session header title text changed to `Vorpal`.
- `vorpal_cli/codex-rs/tui/src/status/card.rs`
  - status card title text changed to `Vorpal`.
- `vorpal_cli/codex-rs/tui/src/onboarding/welcome.rs`
  - welcome text changed to `Welcome to Vorpal`.
- `vorpal_cli/codex-rs/tui/src/status/snapshots/*.snap`
  - status snapshot fixtures updated from `OpenAI Codex` to `Vorpal`.
- `vorpal_cli/docs/config.md`
  - Azure examples updated to `vorpal`.
  - explicit `VORPAL_HOME` example added.

## 7. Example Commands

Interactive (requires TTY):
```bash
VORPAL_HOME=/tmp/codex-test ./codex-rs/target/debug/vorpal --azureai https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview
```

Non-interactive verification:
```bash
VORPAL_HOME=/tmp/codex-test ./codex-rs/target/debug/vorpal exec --skip-git-repo-check --azureai "https://vigilant-local-eastus2-aoai.cognitiveservices.azure.com/openai/responses?api-version=2025-04-01-preview" --json "Reply with the single word OK"
```

## 8. Known Practical Notes

- Build artifacts may still contain an old `target/debug/codex` binary from prior builds.
  - This is not source-of-truth behavior.
  - Source-of-truth CLI binary in this fork is `target/debug/vorpal`.
- The fork keeps many internal `codex_*` symbols/types to keep rebases and cherry-picks tractable.
