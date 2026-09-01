#!/usr/bin/env sh
set -eu

BASE_URL="${BASE_URL:-http://127.0.0.1:${FRONTEND_PORT:-8080}}"

echo "== Services =="
docker compose ps

echo
echo "== Health =="
curl -fsS "$BASE_URL/api/health"; echo

echo
echo "== Dashboard summary first request (cache miss/refresh) =="
time curl -fsS "$BASE_URL/api/dashboard-summary?hours=24" >/tmp/netflow-dashboard-summary.json
cat /tmp/netflow-dashboard-summary.json; echo

echo
echo "== Dashboard summary second request (should be cached) =="
time curl -fsS "$BASE_URL/api/dashboard-summary?hours=24" >/dev/null

echo
echo "== Active PostgreSQL queries =="
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT pid, now()-query_start AS duration, state, LEFT(query,180) AS query
FROM pg_stat_activity
WHERE datname='netflow' AND state <> 'idle'
ORDER BY query_start;
"

echo "Healthy expectation: repeated /api/dashboard-summary calls inside the TTL should not create multiple concurrent COUNT(DISTINCT src_addr/dst_addr) scans."
