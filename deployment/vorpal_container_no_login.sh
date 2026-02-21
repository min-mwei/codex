#!/usr/bin/env bash
set -euo pipefail

image_tag="${1:-${VORPAL_IMAGE_TAG:-vorpal_cli:latest}}"
container_name="${VORPAL_CONTAINER_NAME:-vorpal-cli}"
host_port="${VORPAL_HOST_PORT:-8000}"
container_port="${VORPAL_CONTAINER_PORT:-8000}"
host_azure_dir="${HOME}/.azure"
container_azure_dir="/home/vorpal/.azure"
legacy_container_name="vorpal-cli-proxy-latest"
fallback_image_tag="vorpal-cli-proxy:latest"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is not installed or not in PATH" >&2
  exit 1
fi

if ! docker image inspect "${image_tag}" >/dev/null 2>&1; then
  if [[ "${image_tag}" == "vorpal_cli:latest" ]] && docker image inspect "${fallback_image_tag}" >/dev/null 2>&1; then
    echo "Image ${image_tag} not found; falling back to ${fallback_image_tag}."
    image_tag="${fallback_image_tag}"
  else
    echo "Image ${image_tag} not found locally." >&2
    echo "Build it first (example): ./deployment/build-container.sh ${image_tag}" >&2
    exit 1
  fi
fi

mkdir -p "${host_azure_dir}"

docker rm -f "${container_name}" >/dev/null 2>&1 || true
if [[ "${legacy_container_name}" != "${container_name}" ]]; then
  docker rm -f "${legacy_container_name}" >/dev/null 2>&1 || true
fi

container_id="$(
  docker run -d \
    --user root \
    --name "${container_name}" \
    -p "${host_port}:${container_port}" \
    -e HOST_UID="$(id -u)" \
    -e HOST_GID="$(id -g)" \
    -v "${host_azure_dir}:${container_azure_dir}" \
    "${image_tag}"
)"

echo "Started ${container_name} (${container_id}) from ${image_tag}."
echo "Mounted ${host_azure_dir} to ${container_azure_dir}."
