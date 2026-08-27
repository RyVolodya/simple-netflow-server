# Changelog

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
