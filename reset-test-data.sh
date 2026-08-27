#!/bin/sh
set -eu
echo "WARNING: this deletes ALL Simple NetFlow Server database data and the flow spool."
docker compose down -v --remove-orphans
docker volume rm simple-netflow-server_postgres_data simple-netflow-server_flow_spool 2>/dev/null || true
docker compose up -d --build
