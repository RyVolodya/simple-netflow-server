#!/usr/bin/env sh
set -eu
BASE="${1:-http://localhost:${FRONTEND_PORT:-8080}}"
echo "Checking v0.8.5 health..."
curl -fsS "$BASE/api/health" | grep -q '0.8.5'
echo "Checking retention settings..."
curl -fsS "$BASE/api/settings" >/dev/null
echo "v0.8.5 API checks passed."
