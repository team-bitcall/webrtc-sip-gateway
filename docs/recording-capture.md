# Private recording capture runtime

Task 14a integration checkpoint, 2026-09-12. This is an opt-in stable-media pilot, not customer recording activation. Standalone and legacy gateway startup keep their existing behavior.

## Process and trust boundary

`seat-control` authenticates the existing server-only Bearer/TLS control API and rejects browser Origin headers. It forwards a bounded JSON command to `recording-capture.sock` inside the private seat-state directory. The separate `recording-capture` s6 service owns capture SQLite, reads the call journal and projection through read-only connections, and validates the active projection against private Kamailio RPC. Capture, decoding and periodic finalization do not run in the provisioning process.

The backend derives internal tenant, member, public CDR ID, historical seat and snapshot revision from its persisted CDR/event/binding records. The gateway verifies the projected tenant and deterministic public/manifest IDs, then checks the supplied seat/revision against local admission. Internal membership authority remains the authenticated backend's historical binding; the gateway does not invent a second membership directory.

## Contract

`POST /v1/tenants/{projectedTenantId}/recordings`, existing server credential, JSON body at most 7168 bytes:

```json
{"issuedAtMs":1789200000000,"command":{"action":"status","callId":"<32 lowercase hex>","manifestId":"<32 lowercase hex>"}}
```

`start` adds `binding` with `tenantId`, `gatewayId`, `callId`, `publicCallId`, `membershipId`, and `admission` with `seatId`, `snapshotRevision`. `status` and `finish` accept only the three command fields shown. IDs are computed by the backend service; callers must not supply filenames, SIP credentials, media selectors or arbitrary attribution.

Requests older than 30 seconds or more than 5 seconds ahead are rejected. Within that window, replay is handled by durable immutable call/manifest identity: retrying the same intent cannot start a second capture or rebind it. This reuses transport authentication; it adds no custom signing scheme. Keep clocks synchronized.

Responses contain `callId`, `manifestId`, `state`, and an optional safe `errorCode`. States: `starting`, `capturing`, `finalizing`, `ready`, `stored`, `failed`. **`ready` means private local WAV/manifest complete, not uploaded or billed storage.** The route returns 404 when disabled, 401 for bad authentication, 403 for browser-origin requests, 400 for malformed input, 409 for binding/deadline conflicts and 503 for worker/unavailable evidence.

## Explicit configuration

- `SEAT_MODE=managed`, `SEAT_CALL_EVENTS=1`, `SEAT_RECORDING_ENABLED=1`.
- `SEAT_RECORDING_GATEWAY_ID`: exact canonical origin configured as the backend's gateway provisioning URL.
- `SEAT_STATE_DIR`: existing private durable seat-state directory.
- `SEAT_RECORDING_SPOOL_DIR`: existing canonical owned 0700 directory on a filesystem with total capacity at most **128 MiB** for this pilot. The initializer creates private `pcaps`, `metadata`, `tmp` subdirectories. A directory on a large disk is not a hard bound and is rejected.
- `SEAT_RECORDING_OUTPUT_DIR`: separate existing canonical owned 0700 directory; it cannot overlap/nest with raw spool.

The initializer validates storage before RTPengine receives its recording flags. The worker retries startup through s6 if journal/projection initialization is not yet ready. Files remain 0600. The opt-in backend handoff worker delivers finalized artifacts and acknowledges verified S3 storage; the gateway then reclaims only those acknowledged files. Failed-capture disposal and tombstone retention remain separate policy gates. Use dedicated durable volumes for an actual pilot; the media fixture uses tmpfs and does not prove durability.

The backend additionally requires `teamRecordingCapture: {"enabled": true}` in its existing protected team-auth config, enabled gateway provisioning/call events, configured seat routing, an eligible customer tenant, recording entitlement, and a currently answered complete-enough CDR. It exposes an internal service and an explicit operator command:

```sh
node backend/scripts/run-recording-capture.mjs start TENANT PUBLIC_CALL_ID
node backend/scripts/run-recording-capture.mjs status TENANT PUBLIC_CALL_ID
node backend/scripts/run-recording-capture.mjs finish TENANT PUBLIC_CALL_ID
```

These load the existing protected config and Mongo environment. They add no browser/admin/panel endpoint. Status/finish can still reconcile an existing scoped capture after recording entitlement revocation. Per-agent/global automatic selection is task 15.

## Limits and remaining gates

One worker, at most five captures, 100 stored jobs; bounded per-pass finalization, input packets/bytes, output bytes and duration. Unix reads have total deadlines, strict framing and mode-0600 socket ownership. SIGTERM closes handles/socket; a later restart marks interrupted captures unavailable and retries safe recording stop without deleting voice calls.

Only stable IPv4 PCMU/PCMA 8 kHz, two source legs. Media changes/reorder/overlap remain unsupported and fail closed. Authoritative SDP epochs, replay-tombstone/failed-capture retention, storage-full behavior and broader capacity/codec acceptance remain open. Do not enable customers from this checkpoint.

## Finalized artifact handoff

The same private authenticated `POST /v1/tenants/{projectedTenantId}/recordings`
route accepts three additional commands inside the existing timestamped envelope:

- `list-ready`: `after` is a nonnegative SQLite cursor; `limit` is 1–25. Returns tenant-scoped ready artifacts and a pagination cursor.
- `manifest`: requires `callId` and `manifestId`; returns the exact manifest bytes as Base64, parsed fields and SHA-256.
- `chunk`: requires those IDs, pinned `manifestSha256`, nonnegative `offset` and `length` 1–65536. Returns Base64 bytes, offset, EOF, declared file size and WAV SHA-256.

No client-supplied filesystem paths are accepted. Only private regular files bound
to a ready capture may be read. Commands retain envelope age checks and tenant
scoping. Unix requests remain capped at 8 KiB; replies are capped at 128 KiB.

The backend separately validates attribution and hashes the complete WAV before
queue admission. Reads alone do not acknowledge storage or delete files.

## Verified acknowledgement and cleanup

`acknowledge` requires `callId`, `manifestId`, `manifestSha256`, `sha256` (WAV), and
`sizeBytes`. The backend sends it only after freshly verifying the uploaded object
for a scoped ready recording. No arbitrary filenames or deletion commands exist.
The gateway matches the receipt against its ready manifest, commits an immutable
SQLite receipt and exact private file inventory, then removes only that intent's
WAV, manifest, PCAP and uniquely validated closed metadata. Directory fsync precedes
`stored`. An incomplete cleanup responds `cleanup_pending`; identical acknowledgement
retries work even after some files are missing. Different receipts reject.

At most five pending cleanups are retried per tick with a persisted rotating cursor.
A replaced file or failed unlink/fsync preserves the pending receipt for recovery.
`stored` tombstones prevent duplicate capture on replay; they still count toward the
100-job limit. Tombstone compaction and failed-capture disposal are **not** implemented.
A successful cleanup therefore reclaims audio bytes, not unlimited recording capacity.

The spool is temporary but required for the current PCAP/finalization pipeline.
Long-term audio lives in S3. Files remain until the trusted backend confirms verified
storage; gateway state and receipts must survive restart. S3 lifecycle policy must
preserve objects for the promised customer retention period.
