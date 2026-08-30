#!/bin/sh
set -eu

# One-time maintenance for an upgraded v0.7.7 installation.
# The collector stays up and continues writing to the spool while backend is
# stopped. The spool guard remains active and protects the filesystem.

echo 'Stopping backend ingestion...'
docker compose stop backend
restart_backend() {
  echo 'Starting backend...'
  docker compose start backend >/dev/null 2>&1 || true
}
trap restart_backend EXIT INT TERM

echo 'Applying v0.7.7 index layout...'
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U netflow -d netflow <<'SQL'
ALTER TABLE flow_conversations_5m SET (
  fillfactor = 80,
  autovacuum_vacuum_scale_factor = 0.02,
  autovacuum_analyze_scale_factor = 0.05
);
DROP INDEX IF EXISTS idx_conv5m_last_seen;
DROP INDEX IF EXISTS idx_conv5m_exporter;
DROP INDEX IF EXISTS idx_conv5m_src;
DROP INDEX IF EXISTS idx_conv5m_dst;
DROP INDEX IF EXISTS idx_conv5m_proto;
DROP INDEX IF EXISTS idx_conv5m_inif;
DROP INDEX IF EXISTS idx_conv5m_outif;
DROP INDEX IF EXISTS idx_conv5m_service;
CREATE INDEX IF NOT EXISTS idx_conv5m_src_bucket ON flow_conversations_5m(src_addr, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_conv5m_dst_bucket ON flow_conversations_5m(dst_addr, bucket_start DESC);
CREATE INDEX IF NOT EXISTS idx_conv5m_exporter_bucket_if ON flow_conversations_5m(exporter, bucket_start DESC, in_if, out_if);
CREATE INDEX IF NOT EXISTS idx_conv5m_service_bucket ON flow_conversations_5m(proto, service_port, bucket_start DESC);
SQL

echo 'Rewriting conversation table with fillfactor=80 and reclaiming old bloat...'
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U netflow -d netflow -c "VACUUM (FULL, ANALYZE) flow_conversations_5m;"

echo 'Resetting table statistics so new HOT-update metrics start from zero...'
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U netflow -d netflow -c "SELECT pg_stat_reset_single_table_counters('flow_conversations_5m'::regclass);"

echo 'Storage optimization complete.'
trap - EXIT INT TERM
restart_backend

echo
echo 'Run ./verify-storage.sh after normal traffic has accumulated.'
