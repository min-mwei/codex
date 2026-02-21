#!/usr/bin/env bash
set -euo pipefail

# Run as root only when explicit UID/GID remapping is requested.
if [[ "$(id -u)" -eq 0 ]]; then
  # If HOST_UID is set, adjust the vorpal user's UID/GID to match the host
  # so that bind-mounted files (e.g. ~/.azure) are accessible.
  if [[ -n "${HOST_UID:-}" ]]; then
    cur_uid=$(id -u vorpal)
    cur_gid=$(id -g vorpal)
    target_gid="${HOST_GID:-${HOST_UID}}"

    # Edit /etc/passwd and /etc/group directly instead of using usermod/groupmod,
    # which scan the entire filesystem to update file ownership and hang in containers.
    if [[ "$cur_gid" != "$target_gid" ]]; then
      sed -i "s/^vorpal:x:${cur_gid}:/vorpal:x:${target_gid}:/" /etc/group
      sed -i "s/^\(vorpal:[^:]*:[^:]*:\)${cur_gid}:/\1${target_gid}:/" /etc/passwd
    fi
    if [[ "$cur_uid" != "$HOST_UID" ]]; then
      sed -i "s/^\(vorpal:[^:]*:\)${cur_uid}:/\1${HOST_UID}:/" /etc/passwd
    fi

    # Only chown small writable directories. Skip large read-only build caches
    # (.agency/nodejs ~414M, .npm ~95M) which are world-readable from image build.
    if [[ "$cur_uid" != "$HOST_UID" || "$cur_gid" != "$target_gid" ]]; then
      chown -R vorpal:vorpal /var/log/vorpal /vorpal_base
      chown vorpal:vorpal /home/vorpal
      if [[ -e /home/vorpal/.agency ]]; then
        chown vorpal:vorpal /home/vorpal/.agency
      fi
      if [[ -e /home/vorpal/.agency/logs ]]; then
        chown -R vorpal:vorpal /home/vorpal/.agency/logs
      fi
      # Chown remaining small home subdirs, excluding large read-only caches.
      for d in /home/vorpal/.*; do
        case "${d##*/}" in
          .|..|.agency|.npm) continue ;;
        esac
        [[ -e "$d" ]] || continue
        chown -R vorpal:vorpal "$d"
      done
    fi
  fi

  exec runuser -u vorpal -- "$@"
fi

exec "$@"
