#!/usr/bin/env bash
set -euo pipefail

COMPOSE=${COMPOSE:-docker compose}
FRONTEND_PORT=${FRONTEND_PORT:-$(grep -E '^FRONTEND_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2 || true)}
FRONTEND_PORT=${FRONTEND_PORT:-8080}

echo '== Containers =='
$COMPOSE ps

echo
echo '== Spool API =='
curl -fsS "http://127.0.0.1:${FRONTEND_PORT}/api/spool-status" || true
echo

echo
echo '== Durable spool state =='
$COMPOSE exec -T postgres psql -U netflow -d netflow -c "
SELECT key, value
FROM app_settings
WHERE key LIKE 'flow_spool%'
ORDER BY key;
"

echo
echo '== Spool volume =='
$COMPOSE exec -T backend sh -c '
  ls -lh /data/flows.jsonl /data/flows.jsonl.rotated 2>/dev/null || true
  du -sh /data 2>/dev/null || true
'

echo
echo '== Spool guard (last 30 lines) =='
$COMPOSE logs --tail=30 spool-guard || true

echo
echo 'Healthy expectation:'
echo '  - spool-guard is Up'
echo '  - committed_offset <= active_size unless rotation recovery is active'
echo '  - pending backlog normally returns near 0'
echo '  - total spool stays near the 128 MiB rotation threshold and below the 512 MiB hard limit'
