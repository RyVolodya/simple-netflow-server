## v0.7.7

- Optimized PostgreSQL conversation storage for HOT updates and lower write amplification.
- Removed mutable `last_seen` and legacy single-column conversation indexes.
- Added time-aware indexes on immutable dimensions: source, destination, exporter/interface path, and protocol/service.
- Kept the unique `(bucket_start, conv_key)` index used by service-conversation UPSERTs.
- Set `flow_conversations_5m` `fillfactor=80` with more aggressive autovacuum/analyze thresholds.
- Removed `service_port`/`service_side` assignments from conflict updates so indexed service identity remains immutable.
- Flow time filters now use indexed `bucket_start` for candidate selection while retaining exact `received_at` boundary checks.
- Latest Conversations restricts queries to the newest buckets before sorting, eliminating the need for a global mutable last-seen index.
- Added `optimize-conversation-storage.sh` for one-time upgraded-table rewrite/reclaim and HOT-ready page layout.
- Extended `verify-storage.sh` with HOT update percentage, index/data ratio, and index usage/size.

## v0.7.6

- Fixed inconsistent known-port labels across the GUI.
- Added `/api/service-labels` as the shared effective service-name catalog for built-in well-known ports plus custom Port descriptions.
- Custom descriptions override built-in names for the same protocol/port.
- Dashboard, Latest Conversations, Flows Detailed/Summary, and other tables now render known services consistently, e.g. `SNMP UDP/161` and `SSH TCP/22`.
- Unknown ports still fall back to `TCP/<port>` or `UDP/<port>`.

## v0.7.5
- Fixed frontend/backend API version guard: v0.7.4 frontend still expected backend 0.7.3 and falsely showed `Backend 0.7.4 detected. Rebuild backend for v0.7.4 API.`
- Synchronized frontend, backend `APP_VERSION`, Docker Compose, health endpoint expectation, and displayed release version to 0.7.5.
- No database schema reset is required.

## v0.7.4

- Settings layout: Users now shares the same row as Collector.
- Port descriptions moved to the full-width bottom row.
- No database or API changes.

## v0.7.3
- Added SNMP interface alias display across the GUI.
- Interfaces with `ifAlias` are rendered as `ifName (ifAlias)`, for example `vlan52 (Home LAN)`.
- Applied to Dashboard Top Interfaces, Dashboard Latest Conversations, Flows, Conversation interface mode, and interface filters.
- Falls back to `ifName`, `ifDescr`, or `ifIndex N` when no alias is available.
- Alias remains SNMP metadata only and does not change aggregation keys or stored NetFlow conversation data.

# Changelog

## v0.7.3

- Added Settings → Port descriptions with administrator CRUD.
- Add one or many port descriptions in a single Add dialog.
- Unique descriptions are keyed by protocol + port and can be edited or deleted.
- Custom labels are applied without rewriting flow/conversation data.
- Dashboard Top Applications and Latest Conversations show labels such as `Proxmox TCP/8006`.
- Flows detailed/summary views use the same custom service labels.
- Retains v0.7.1 service-oriented aggregation and atomic spool-offset transactions.

## v0.7.1
- Reworked 5-minute conversation aggregation from full 5-tuple to **service-oriented directional conversations**.
- Service endpoint may be on either Source or Destination; `service_port` and `service_side` are stored explicitly.
- Stable service ports are kept in the aggregation key while identified client ephemeral ports are removed, reducing row cardinality substantially for repeated HTTPS, Zabbix, SMB, database and similar traffic.
- Ambiguous high-port/custom traffic falls back to the exact source/destination port pair to avoid incorrect merging.
- Exporter, source/destination IP, protocol, input interface and output interface remain directional key dimensions.
- Added an in-memory micro-batch conversation cache; default durable flush is every 10 seconds or 10,000 records.
- Conversation UPSERTs and `flow_spool_offset` now commit in the **same PostgreSQL transaction**, preventing double-counting after a crash between DB write and offset update.
- Dashboard renamed **Latest 10 Flows** to **Latest 10 Conversations** and now shows Last Seen, Service, Packets and represented Flows.
- Application/port aggregation uses the detected service port instead of assuming Destination is always the service.
- `verify-storage.sh` now reports compression ratio, service-detection coverage and table size.
- Retains v0.7.0 5-minute buckets, interface-to-interface Conversation mode, 24h detailed retention, 30d statistics, spool rotation and spool-guard protection.


## v0.6.7
- Fixed History device dropdown labels showing `(undefined)`.
- `/api/exporters` returns the device IP in `exporter`; History incorrectly read `ip`.
- Exporter filtering now submits the correct IP for Exporter and Interface historical views.
- History filter controls are context-aware: Exporter is available only where the aggregate table retains exporter dimension, Interface only for Interface history, Protocol only for Application history.
- This avoids silently applying a device filter to Source/Destination/Application/Total history where the current aggregate schema cannot correlate those rows back to an exporter.
- Keeps the v0.6.5 spool rotation/spool-guard protections and v0.6.6 API compatibility fix.


## v0.6.6
- Fixed a stale frontend API compatibility check that still expected backend version `0.6.4`.
- Frontend now correctly accepts backend version `0.6.6`.
- Updated sidebar, Settings/Application, realtime defaults and compatibility message to the same version.
- Retains the v0.6.5 spool rotation and spool-guard protections.


## v0.6.5
- Reworked GoFlow2 spool handling to prevent unbounded `flows.jsonl` growth.
- Added crash-safe spool rotation: rename -> SIGHUP collector -> ingest race-window tail -> delete only after PostgreSQL commit.
- Default spool rotation threshold is 128 MiB (`SPOOL_ROTATE_BYTES`).
- Backend now mounts `flow_spool` read/write and shares the collector PID namespace only to send GoFlow2 `SIGHUP`.
- Added independent `spool-guard`: pauses the collector at 1 GiB spool usage and resumes below 768 MiB, protecting the host filesystem if PostgreSQL/backend is unavailable.
- Added recovery metadata so an interrupted rotation is completed after backend restart without re-importing the already committed prefix.
- Existing large spools are compacted automatically after the backend catches up.


## v0.6.4
- Fixed History HTTP 500 when applying filters.
- Added missing `timedelta` import used by History retention-window calculations.
- Aligned backend/frontend/Compose version reporting to 0.6.4.
- History continues to clamp aggregate queries between Statistics retention and Raw flows retention boundaries.


## v0.6.3
- Added History tab backed by aggregate tables.
- Retention labels are read dynamically from Settings.
- History is automatically limited to data older than Raw flows retention and within Statistics retention.
- Views: Source IP, Destination IP, Exporter, Interface, Application/Port, Total traffic.
- Filters, pagination, Traffic/Packets/Flows and aggregate bucket ranges.


## v0.6.2

- Added a new **Conversation** tab.
- Added Flow-equivalent filters: period/custom range, exporter, protocol, source/destination IP, source/destination port and interface.
- Added directional `Source IP -> Destination IP` aggregation with summed traffic, packets and flow count.
- Added **Table / Chart** view switch.
- Added Top N selector: 10, 25, 50 or 100 conversations.
- Conversation results are always ordered by total traffic descending.
- Added table pagination and 30-second background refresh using the current filter snapshot.
- Added `/api/conversations` and `/api/conversations/count`.
- Application version bumped to 0.6.2.

## 0.6.1

- Fixed Exporters Delete button crash caused by calling `.find()` on a NodeList.
- Delete progress dialog now opens correctly after confirmation for Idle exporters.
- Active exporters no longer have a silent disabled Delete button; clicking Delete now shows a clear message that NetFlow export must be stopped and the exporter must become Idle first.
- Frontend host port is now configurable with `FRONTEND_PORT` (default 8080), so `FRONTEND_PORT=3080` works without editing Compose.


## v0.6.1

### Exporter deletion
- Reworked exporter deletion as an asynchronous backend job.
- Added a real progress dialog in Exporters.
- Raw flows are deleted from daily partitions in bounded batches so progress can be reported.
- Progress stages include exporter validation, raw flows, interfaces/SNMP, exporter aggregates, exporter record, and statistics rebuild.
- Backend errors are displayed directly in the progress dialog instead of failing silently.
- Added `GET /api/exporters/delete-jobs/{job_id}` for job status.
- `POST /api/exporters/delete` now starts a delete job and returns immediately.
- Existing legacy exporter-delete routes remain available for compatibility and also start jobs.
- After completion the Exporters list and Dashboard refresh automatically.

### Version
- Application version bumped to 0.6.1.
