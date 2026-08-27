
Lightweight Docker-first NetFlow/IPFIX/sFlow collector and analyzer with PostgreSQL, SNMP enrichment, role-based authentication, batch ingestion, 1-minute dashboard aggregates, and optimized raw-flow storage.




## Conversation view (v0.6.2)

The **Conversation** tab aggregates directional traffic by `Source IP -> Destination IP`. It uses the same filters as Flows (period/custom range, exporter, protocol, source/destination, ports and interface).

Two views are available:

- **Table** - Source, Destination, total Traffic, Packets and number of flow records, always ordered by Traffic descending.
- **Chart** - doughnut chart plus ranked detail list. Choose Top 10, 25, 50 or 100 conversations.

The selected 1/3/6/12/24 hour period can be frozen with **Apply filters**, matching the analysis-snapshot behavior of Flows.

## Exporter deletion progress (v0.6.2)

Deleting an Idle exporter is now an asynchronous operation with a visible progress dialog. The backend removes raw flows from daily partitions in batches, then removes interfaces/SNMP metadata, exporter-scoped aggregates and the exporter inventory record. Finally, dashboard statistics are rebuilt from the remaining flows.

The progress dialog reports the current stage, percentage and `deleted / total` raw-flow count. If the backend returns an error, the message is shown in the dialog.

An exporter must be Idle before deletion. If the device continues exporting NetFlow, disable export first and wait until it becomes Idle.

Delete API:

```text
POST /api/exporters/delete
GET  /api/exporters/delete-jobs/{job_id}
```

## What is new in v0.6.2

- No `flow-spool-init` container.
- Dashboard now has 8 cards, including total discovered interfaces.
- Total Traffic is the first Dashboard chart.
- Top Devices displays `hostname (IP)` when SNMP naming is available.
- Settings layout was reorganized and password changes moved to Users.
- Logout is now an icon button.

### Upgrade from v0.5.7

Use `--remove-orphans` once so the old exited init container is removed:

```bash
docker compose down --remove-orphans
docker compose up -d --build --remove-orphans
```

Do not use `docker compose down -v` unless you intentionally want to delete PostgreSQL and flow spool data.

## Storage retention defaults

Fresh installations use:

- Detailed raw flows: **12 hours** by default, minimum **1 hour**.
- Aggregated statistics: **30 days** by default, minimum **6 hours**.

Administrators can change both values in **Settings → Storage**. Existing saved values are preserved when upgrading.

## Default login

For a new database:

```text
Username: admin
Password: netflow
```

The initial administrator must change the password on first login. Existing installations keep their users and passwords.

## What is new in v0.5.2

### Storage optimization

- `flows` is migrated to **daily PostgreSQL RANGE partitions** by `received_at`.
- Existing raw flows are copied to the new partitions and the row count is verified before the legacy table is removed.
- The oversized v0.5.1 indexes are replaced with a smaller set:
  - `received_at DESC`
  - `exporter`
  - `src_addr`
  - `dst_addr`
  - `proto`
  - `(exporter, in_if)`
  - `(exporter, out_if)`
- Removed the redundant single-column `in_if` / `out_if` indexes and the timestamp duplication from all secondary composite indexes.
- Old daily partitions are dropped during retention cleanup; only the boundary partition needs row-level DELETE for an exact hour cutoff.
- Partitions for the current day and the next two days are created automatically.

### Separate retention

Settings → Storage now has independent retention for:

- **Raw flows** — detailed rows used by the Flows page.
- **Statistics** — 1-minute aggregates used by Dashboard charts and Top-N analytics.

Both support days + hours with a minimum of 1 hour. During upgrade, the existing retention value is preserved for both settings so the upgrade does not unexpectedly delete data.

### Storage visibility

Settings → Storage now shows:

- Raw flow data
- Raw indexes
- Aggregates
- Total database size

This makes it possible to see directly whether data or indexes are consuming disk space.

## Important upgrade note

The first start from v0.5.1 performs a **one-time raw-flow migration**. With millions of flows this can take noticeable time and needs temporary free disk space because PostgreSQL must hold the old table while the new partitioned rows are being created.

The backend logs progress:

```text
[v0.5.2] Migrating raw flows to daily partitions. This is a one-time operation...
[v0.5.2] Partition migration complete: 2613582 flows preserved.
```

The migration runs before the collector ingester starts. If row verification fails, the transaction is rolled back and the backend does not start on a partial schema.

## Upgrade from v0.5.1

Preserve the existing PostgreSQL volume:

```bash
docker compose down
```

Replace the project files with v0.6.2, then:

```bash
docker compose build --no-cache backend
docker compose up -d --force-recreate
```

Watch the one-time migration:

```bash
docker compose logs backend -f
```

Do **not** use:

```bash
docker compose down -v
```

unless you intentionally want to delete the PostgreSQL database.

## New installation

```bash
unzip simple-netflow-server-v0.6.2.zip
cd simple-netflow-server-v0.6.2
docker compose up -d --build
```

Open:

```text
http://SERVER-IP:8080
```

NetFlow/IPFIX: UDP `2055`  
sFlow: UDP `6343`

## Recommended retention starting point

For a busy installation, a practical starting point is:

```text
Raw flows:   1 day
Statistics: 30 days
```

Raw retention controls detailed per-flow analysis. Statistics retention keeps the compact Dashboard history much longer.

## Verify partitioning

```bash
docker compose exec postgres psql -U netflow -d netflow -c "
SELECT inhrelid::regclass AS partition
FROM pg_inherits
WHERE inhparent='flows'::regclass
ORDER BY 1;
"
```

## Verify index sizes

```bash
docker compose exec postgres psql -U netflow -d netflow -c "
SELECT
  c.relname AS partition,
  pg_size_pretty(pg_relation_size(c.oid)) AS data,
  pg_size_pretty(pg_indexes_size(c.oid)) AS indexes
FROM pg_inherits i
JOIN pg_class c ON c.oid=i.inhrelid
WHERE i.inhparent='flows'::regclass
ORDER BY c.relname;
"
```

## Useful checks

```bash
docker compose ps
docker compose logs backend --tail=100
curl http://127.0.0.1:8080/api/health
```

Expected:

```json
{"status":"ok","version":"0.6.2"}
```


## Clean test reset
To destroy the PostgreSQL database and flow spool completely and let v0.6.2 create a fresh schema:

```bash
docker compose down -v --remove-orphans
docker volume rm simple-netflow-server_postgres_data simple-netflow-server_flow_spool 2>/dev/null || true
docker compose up -d --build
```

This intentionally deletes all users, settings, SNMP inventory, raw flows, aggregates, sessions and the collector spool.

## Exporter purge
Delete is allowed only while the exporter is Idle. The purge removes the exporter inventory, SNMP interfaces, all matching raw flows and exporter/interface aggregates; shared aggregates are rebuilt from the remaining raw flows. Stop NetFlow export on the device first, otherwise the exporter will be discovered again on its next flow packet.


## Flows summary mode
The Flows page includes a **Detailed / Summary** switch. Summary aggregates the current filter selection and reports traffic, packets and flow-record counts by IP/protocol/port. For a Source IP filter it groups by destination IP/protocol/destination port; for a Destination IP filter it groups by source IP/protocol/source port.


## Exporter purge (v0.6.2)

Administrators can delete an Idle exporter from **Exporters**. The purge removes its raw flows across all daily partitions, SNMP/interface metadata, exporter-scoped aggregates and inventory record. Global dashboard aggregates are cleared immediately and rebuilt in the background from remaining raw flows. If the device continues exporting NetFlow, it will be discovered again.
