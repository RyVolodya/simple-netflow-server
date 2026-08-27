#!/bin/sh
set -eu

TARGET="simple-netflow-server_postgres_data"
SOURCE="${1:-}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker command not found" >&2
  exit 1
fi

if [ -z "$SOURCE" ]; then
  # Prefer the last known working release before v0.4.0.
  for candidate in \
    simple-netflow-server-v0.3.9_postgres_data \
    simple-netflow-server-v0.3.8_postgres_data \
    simple-netflow-server-v0.3.7_postgres_data \
    simple-netflow-server-v0.3.6_postgres_data \
    simple-netflow-server-v0.3.5_postgres_data \
    simple-netflow-server-v0.3.4_postgres_data \
    simple-netflow-server-v0.3.3_postgres_data \
    simple-netflow-server-v0.3.2_postgres_data \
    simple-netflow-server-v0.3.1_postgres_data \
    simple-netflow-server-v0.3.0_postgres_data
  do
    if docker volume inspect "$candidate" >/dev/null 2>&1; then SOURCE="$candidate"; break; fi
  done
fi

if [ -z "$SOURCE" ]; then
  echo "No previous Simple NetFlow PostgreSQL volume found."
  echo "Available candidates:"
  docker volume ls --format '{{.Name}}' | grep -E 'simple-netflow-server.*postgres_data$' || true
  echo "Run again with the source volume name, e.g.:"
  echo "  ./migrate-old-volume.sh simple-netflow-server-v0.3.9_postgres_data"
  exit 2
fi

if ! docker volume inspect "$SOURCE" >/dev/null 2>&1; then
  echo "Source volume not found: $SOURCE" >&2
  exit 2
fi

if [ "$SOURCE" = "$TARGET" ]; then
  echo "Source is already the stable volume: $TARGET"
  exit 0
fi

echo "Stopping Simple NetFlow Server containers..."
docker compose down >/dev/null 2>&1 || true

echo "Copying PostgreSQL data: $SOURCE -> $TARGET"
docker volume create "$TARGET" >/dev/null

docker run --rm -v "$SOURCE":/from:ro -v "$TARGET":/to alpine:3.20 sh -c '
  rm -rf /to/* /to/.[!.]* /to/..?* 2>/dev/null || true
  cd /from
  tar cf - . | tar xpf - -C /to
'

echo "Migration complete. Start v0.4.1 with: docker compose up -d --build"
