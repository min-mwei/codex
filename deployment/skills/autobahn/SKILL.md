---
name: autobahn
description: Deploy a project under /vorpal_base/context to local Docker runtime by reading project instructions for docker build hints, locating the Dockerfile, building the image, and running the container. Use when a project already includes Docker instructions/Dockerfile and the user wants a local container deployment.
---

# Autobahn

Deploy web projects to local Docker using project-provided instructions.

## Scope

- Support simple projects that already include Docker instructions.
- Target runtime is only local Docker (`local-docker`).
- Resolve project paths only under `/vorpal_base/context`.

## Workflow

1. Read project instruction files (`README*`, docker/install/setup markdown).
2. If instructions include `docker compose up ...` and a compose file exists, run compose mode.
3. Otherwise, extract first `docker build ...` hint when present.
4. Locate Dockerfile from the hint or by searching project files.
5. Build image with discovered Dockerfile and context.
6. Run container on local Docker with auto-published ports (`-P`).

## Command

```bash
scripts/deploy_local_docker.py --project <project-under-/vorpal_base/context>
```

Example:

```bash
scripts/deploy_local_docker.py --project my-webapp
```

## Optional Flags

- `--build-only`: build image without running container.
- `--dockerfile <path>`: override detected Dockerfile path.
- `--build-context <path>`: override detected build context path.
- `--image-tag <tag>`: override image tag.
- `--container-name <name>`: override container name.
- `--no-replace`: do not remove existing container with same name.
- `--dry-run`: show commands without executing.
- `--force-dockerfile`: ignore compose hints/files and force Dockerfile mode.

## Output Requirements

- Show discovered instruction source and docker build hint when found.
- Show selected deployment mode (`docker-compose` or `dockerfile`).
- Show selected Dockerfile and build context in Dockerfile mode.
- Show executed `docker build` and `docker run` commands.
- Show executed `docker compose` commands in compose mode.
- Show container id and published ports when run succeeds.
