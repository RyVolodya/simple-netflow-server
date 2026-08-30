# Simple NetFlow Server v0.7.7

Lightweight Docker-first NetFlow/IPFIX/sFlow collector and analyzer using GoFlow2, FastAPI, PostgreSQL and nginx.

## v0.7.7 storage model

v0.7.7 keeps the 5-minute conversation architecture introduced in v0.7.0, but reduces cardinality further with **service-oriented aggregation**.

**Old raw model:** one incoming NetFlow record = one PostgreSQL row.

**v0.7.0 model:** one row per full directional 5-tuple + exporter/interface path + 5-minute bucket.

**v0.7.7 model:** one row per directional service conversation. The key keeps:

- exporter
- source IP
- destination IP
- protocol
- detected service port and whether it is on Source or Destination
- input interface
- output interface
- 5-minute bucket

When a stable service endpoint is detected, the changing client ephemeral port is not part of the key. For example:

```text
192.168.150.3:41318 -> 139.59.147.198:10050
192.168.150.3:41332 -> 139.59.147.198:10050
192.168.150.3:41384 -> 139.59.147.198:10050
```

is stored as one directional service conversation for `TCP/10050`, provided exporter/interface path and bucket are the same. The service can also be on Source, e.g. `145.1.1.1:443 -> client:62345`.

Detection is conservative. Known application ports and well-known/registered-vs-ephemeral patterns are collapsed; ambiguous high-port/custom traffic keeps the full port pair so unrelated sessions are not merged.

Each stored row accumulates `bytes`, `packets`, `flow_count`, `first_seen` and `last_seen`.

The backend keeps a short in-memory micro-batch cache and flushes by default every **10 seconds** or **10,000 records**. Conversation UPSERTs and the spool offset are committed in the same PostgreSQL transaction, so a restart cannot replay an already committed batch and double-count it.

The detailed table remains `flow_conversations_5m`; the legacy raw `flows` table is not written.


## v0.7.7 PostgreSQL storage optimization

Conversation aggregation was already reducing incoming NetFlow records by more than an order of magnitude, but the old mutable-column indexes caused severe PostgreSQL write amplification. v0.7.7 changes the index strategy so frequently updated columns (`last_seen`, `received_at`, bytes, packets and flow count) are not indexed.

The conversation table now uses `fillfactor=80` and lower autovacuum thresholds. Old single-column indexes are removed and replaced with time-aware indexes built only from immutable conversation dimensions:

- `(src_addr, bucket_start)`
- `(dst_addr, bucket_start)`
- `(exporter, bucket_start, in_if, out_if)`
- `(proto, service_port, bucket_start)`
- the existing unique `(bucket_start, conv_key)` index remains the UPSERT conflict key

Default Latest Conversations queries first restrict work to the newest 5-minute buckets and only then sort by `received_at`, so a global mutable `last_seen` index is no longer required. Time filters use `bucket_start` as the indexable coarse predicate and retain `received_at` as the exact boundary check.

For an **existing upgraded database**, run the one-time maintenance script after v0.7.7 is running:

```bash
./optimize-conversation-storage.sh
```

It temporarily stops only the backend ingester, keeps the collector/spool running, applies the v0.7.7 index layout, rewrites `flow_conversations_5m` with `VACUUM FULL` so `fillfactor=80` applies to existing pages, resets table counters, and restarts the backend. `VACUUM FULL` requires temporary free disk space and takes an exclusive lock on this table, which is why it is not run automatically at application startup.

After normal traffic accumulates, check HOT-update efficiency and index/data ratio with:

```bash
./verify-storage.sh
```

## Conversation

Conversation has two grouping modes:

1. **Source → Destination** — aggregate traffic between IP endpoints.
2. **Input interface → Output interface** — show traffic routed through a device from one interface to another.

Interface mode includes device, input interface, output interface, traffic, packets, represented flow count and last-seen time. Select an exporter before selecting a specific input/output interface to avoid ambiguous ifIndex values across devices.

## Flows

The Flows page displays the latest 5-minute service-oriented conversation buckets rather than individual raw records. The `Flows` column shows how many original NetFlow records were merged into the row, and `Last seen` is updated when a newer matching record is received.

## History

The separate History menu item remains removed in v0.7.7. Long-retention 1-minute statistics remain in PostgreSQL for Dashboard/Top-N analytics. Conversation is the operational detailed view.

## Retention defaults

Fresh installations:

- Detailed conversations: **24 hours**
- Statistics: **30 days**

Both remain configurable in **Settings → Storage**.

## Install

```bash
unzip simple-netflow-server-v0.7.7.zip
cd simple-netflow-server-v0.7.7
cp .env.example .env
# edit .env if needed
docker compose up -d --build
```

Default web port: `8080`. Set `FRONTEND_PORT=3080` in `.env` if you use port 3080.

NetFlow/IPFIX: UDP `2055`  
sFlow: UDP `6343`

## Upgrade from v0.7.0 / v0.6.7

Preserve existing volumes:

```bash
docker compose down --remove-orphans
docker compose up -d --build --remove-orphans
```

v0.7.7 continues to avoid legacy raw writes. Existing v0.7.0 full-tuple conversation rows remain readable and age out under the configured detailed retention; new records use service-oriented keys.

For a **test installation** where old flow data is not needed, the cleanest way to measure the new storage model is a full data reset:

```bash
docker compose down -v --remove-orphans
docker compose up -d --build --remove-orphans
```

This deletes PostgreSQL data, users/settings and the flow spool, so use it only when a full reset is intended.

## Verify

```bash
docker compose ps
docker compose logs backend --tail=200
curl http://127.0.0.1:${FRONTEND_PORT:-8080}/api/health
```

Expected:

```json
{"status":"ok","version":"0.7.7"}
```

Check service-conversation compression:

```bash
docker compose exec postgres psql -U netflow -d netflow -c "
SELECT
  count(*) AS conversation_rows,
  sum(flow_count) AS represented_flows,
  pg_size_pretty(pg_total_relation_size('flow_conversations_5m')) AS conversation_size
FROM flow_conversations_5m;
"
```

A useful compression indicator is:

```text
represented_flows / conversation_rows
```

For example, `20` means one stored conversation row represents about 20 original NetFlow records on average.

## Spool protection

v0.7.7 retains the v0.6.5 crash-safe spool rotation and `spool-guard` sidecar. The backend rotates consumed `flows.jsonl` and the guard pauses the collector if the spool reaches the configured emergency threshold.

## Custom port descriptions

Administrators can manage custom service/application labels in **Settings → Port descriptions**. Use **Add** to enter one or many rows and save them in one operation. Existing entries can be edited or deleted.

Example:

```text
Protocol: TCP
Port: 8006
Description: Proxmox
Display: Proxmox TCP/8006
```

Descriptions are metadata stored separately from conversation data. Editing or deleting a description does not rewrite or re-aggregate NetFlow records. Custom labels are used by Dashboard Top Applications, Latest Conversations, and Flows service/port displays.
