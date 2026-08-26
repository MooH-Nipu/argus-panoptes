#!/bin/sh
set -eu

mkdir -p "${CONFIG_DIR:-/data}"
for name in settings.yaml whitelist.yaml protect_list.yaml; do
  if [ ! -e "${CONFIG_DIR:-/data}/$name" ]; then
    cp "/app/$name" "${CONFIG_DIR:-/data}/$name"
  fi
done

exec "$@"
