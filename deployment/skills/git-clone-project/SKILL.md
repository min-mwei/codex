---
name: git-clone-project
description: Clone Git repositories under /vorpal_base/context with safe destination checks, optional branch selection, shallow or full history control, submodule support, and Azure DevOps bearer-token auth via Azure CLI. Use when a user asks to "git clone" a project, copy a repo locally, or set up source code from GitHub/GitLab/Bitbucket/Azure DevOps.
---

# Git Clone Project

Clone repositories with `scripts/clone_project.sh` to enforce safe defaults and consistent behavior.

The skill includes `scripts/git` as a bundled git wrapper. It prefers Linux git and falls back to `git.exe` (WSL/Git for Windows) when needed.

## Workflow

1. Collect the repository URL and optional destination path under `/vorpal_base/context`.
2. Ask whether to clone a specific branch, include submodules, and keep shallow history or full history.
3. For Azure DevOps HTTPS repos, the script auto-attempts Azure CLI bearer auth; use `--ado-az-login` to require token auth (fail fast if unavailable).
4. Run the script with the chosen options.
5. Verify clone success by checking remote URL, current branch, and shallow status.

## Command

```bash
scripts/clone_project.sh <repo-url> [destination] [--branch <name>] [--depth <n>] [--full-history] [--recursive] [--ado-az-login] [--ado-resource <id-or-uri>]
```

### Defaults

- Always clone under `/vorpal_base/context`.
- Omitted destination resolves to `/vorpal_base/context/<repo-name>`.
- Relative destination resolves under `/vorpal_base/context`.
- Absolute destination is allowed only if it remains under `/vorpal_base/context`.
- Clone with `--depth 1` unless `--full-history` is set.
- Refuse to clone into an existing non-empty directory.
- Public GitHub repos clone without additional auth.
- Azure DevOps repos auto-attempt `az account get-access-token` and set `git -c http.extraheader="AUTHORIZATION: bearer <token>"` when available.
- `--ado-az-login` requires Azure CLI token auth for Azure DevOps clones (recommended for private repos).
- Default ADO token resource is `499b84ac-1321-427f-aa17-267ca6975798`.

## Examples

```bash
scripts/clone_project.sh https://github.com/octocat/Hello-World.git
scripts/clone_project.sh git@github.com:org/repo.git repo-local --branch main --recursive
scripts/clone_project.sh https://github.com/org/repo.git /vorpal_base/context/team/repo --full-history
scripts/clone_project.sh "https://dev.azure.com/medeina/MSECAI%20Applied%20Research/_git/Invictus" --ado-az-login
scripts/clone_project.sh "https://dev.azure.com/medeina/MSECAI%20Applied%20Research/_git/Invictus"
```

## Verification

```bash
git -c safe.directory='*' -C <destination> remote -v
git -c safe.directory='*' -C <destination> branch --show-current
git -c safe.directory='*' -C <destination> rev-parse --is-shallow-repository
```

## Troubleshooting

- Resolve `Permission denied (publickey)` by using the right SSH key or an HTTPS URL.
- Resolve `Repository not found` by checking the URL and access permissions.
- Use `--full-history` when shallow clone breaks tooling that needs full commit history.
- For Azure DevOps `401/403`, run `az login` with an identity that has access to the project/repository and retry with `--ado-az-login`.
- If the environment shell cannot resolve `git`, run `scripts/clone_project.sh` from this skill directory so it can use the bundled `scripts/git` wrapper.
