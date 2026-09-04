#!/usr/bin/env sh
set -eu

echo "== containers =="
docker compose ps

echo "== backend version =="
curl -fsS http://127.0.0.1:${FRONTEND_PORT:-8080}/api/health || true
echo

echo "== retention settings =="
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT key,value FROM app_settings
WHERE key IN ('raw_retention_hours','stats_retention_days','stats_retention_hours')
ORDER BY key;"

echo "== v0.8.4 statistics storage =="
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT
  count(*) AS historical_rows,
  coalesce(sum(flows),0) AS represented_flows,
  pg_size_pretty(pg_total_relation_size('flow_stats_conversations_5m')) AS historical_size
FROM flow_stats_conversations_5m;"

echo "== latest historical bucket =="
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT min(bucket_start) AS oldest, max(bucket_start) AS newest
FROM flow_stats_conversations_5m;"
