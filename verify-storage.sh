#!/bin/sh
set -eu

echo '=== Containers ==='
docker compose ps

echo
echo '=== API health ==='
port="${FRONTEND_PORT:-8080}"
curl -fsS "http://127.0.0.1:${port}/api/health" || true

echo
echo '=== Service conversation compression ==='
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT
  count(*) AS conversation_rows,
  coalesce(sum(flow_count),0) AS represented_flows,
  round(coalesce(sum(flow_count),0)::numeric / greatest(count(*),1), 2) AS flows_per_row,
  round(100.0 * count(*) FILTER (WHERE service_port IS NOT NULL) / greatest(count(*),1), 2) AS service_detection_pct,
  pg_size_pretty(pg_relation_size('flow_conversations_5m')) AS data_size,
  pg_size_pretty(pg_indexes_size('flow_conversations_5m')) AS index_size,
  pg_size_pretty(pg_total_relation_size('flow_conversations_5m')) AS conversation_size
FROM flow_conversations_5m;
"

echo '=== Service side distribution ==='
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT coalesce(service_side,'ambiguous/full-port') AS service_side,
       count(*) AS rows,
       coalesce(sum(flow_count),0) AS represented_flows
FROM flow_conversations_5m
GROUP BY 1
ORDER BY rows DESC;
"


echo '=== HOT update efficiency ==='
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT
  n_live_tup,
  n_dead_tup,
  n_tup_ins,
  n_tup_upd,
  n_tup_hot_upd,
  round(100.0 * n_tup_hot_upd / NULLIF(n_tup_upd,0), 2) AS hot_update_pct
FROM pg_stat_user_tables
WHERE relname='flow_conversations_5m';
"

echo '=== Conversation index/data ratio ==='
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT
  pg_size_pretty(pg_relation_size('flow_conversations_5m')) AS data_size,
  pg_size_pretty(pg_indexes_size('flow_conversations_5m')) AS index_size,
  pg_size_pretty(pg_total_relation_size('flow_conversations_5m')) AS total_size,
  round(pg_indexes_size('flow_conversations_5m')::numeric / NULLIF(pg_relation_size('flow_conversations_5m'),0), 2) AS index_to_data_ratio;
"

echo '=== Conversation index usage ==='
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT indexrelname, idx_scan, pg_size_pretty(pg_relation_size(indexrelid)) AS size
FROM pg_stat_user_indexes
WHERE relname='flow_conversations_5m'
ORDER BY pg_relation_size(indexrelid) DESC;
"

echo '=== Largest public tables ==='
docker compose exec -T postgres psql -U netflow -d netflow -c "
SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC
LIMIT 15;
"
