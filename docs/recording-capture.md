# Private recording capture runtime

Task 14 recording-capture pilot, 2026-09-12. Customer policy and automatic
selection remain a Task 15 decision; standalone and legacy gateway startup keep
their existing behavior.

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
- `SEAT_RECORDING_CAPTURE_MODE`: defaults to `pcap`. `subscription` is an explicit native RTPengine-subscription pilot and adds the named loopback RTPengine interface `recording/127.0.0.1` at startup. Do not select it unless that loopback-only interface is available to the recorder.
- `SEAT_RECORDING_FAILED_RETENTION_SECONDS` and `SEAT_RECORDING_STORED_RETENTION_SECONDS`: retention is disabled unless **both** are explicit ASCII decimal durations in the inclusive range 1–31,536,000 seconds. Supplying only one, zero, or an out-of-range value prevents the recording runtime from starting.

The initializer validates storage before RTPengine receives its recording flags. The worker retries startup through s6 if journal/projection initialization is not yet ready. Files remain 0600. The opt-in backend handoff worker delivers finalized artifacts and acknowledges verified S3 storage; the gateway then reclaims only those acknowledged files. Retention code is present but remains off without its paired explicit durations; enabling customer policy is a separate Task 15 decision. Use dedicated durable volumes for an actual pilot; the media fixture uses tmpfs and does not prove durability.

The backend additionally requires `teamRecordingCapture: {"enabled": true}` in its existing protected team-auth config, enabled gateway provisioning/call events, configured seat routing, an eligible customer tenant, recording entitlement, and a currently answered complete-enough CDR. It exposes an internal service and an explicit operator command:

```sh
node backend/scripts/run-recording-capture.mjs start TENANT PUBLIC_CALL_ID
node backend/scripts/run-recording-capture.mjs status TENANT PUBLIC_CALL_ID
node backend/scripts/run-recording-capture.mjs finish TENANT PUBLIC_CALL_ID
```

These load the existing protected config and Mongo environment. They add no browser/admin/panel endpoint. Status/finish can still reconcile an existing scoped capture after recording entitlement revocation. Per-agent/global automatic selection is task 15.

## Limits, retirement, and remaining gates

One worker permits at most five active captures and 100 capture rows. Periodic finalization considers at most five capturing rows, and an enabled retention sweep considers at most five terminal failed/stored rows per pass. Input packets/bytes, output bytes and duration are bounded. Unix reads have total deadlines, strict framing and mode-0600 socket ownership. SIGTERM closes handles/socket; a later restart marks interrupted captures unavailable and retries safe recording stop without deleting voice calls.

Retirement is deliberately conservative. It proceeds only after the configured failed/stored age, terminal journal evidence, no active CDR from the trusted RPC view, and RTPengine NG `query` confirmation that the call is gone. Failed rows additionally require an exact private-file inventory and identity revalidation before unlinking; stored rows require the durable cleanup receipt. A failed check leaves the row and files in place for a later bounded retry.

The default `pcap` mode remains a stable-media guard: one audio IPv4 G.711
PT0/PT8 source per leg, with two source legs. It rejects unsupported media epochs.
The opt-in `subscription` mode uses two native RTPengine subscriptions bound to
the exact ordered from-tags. It accepts a source port/SSRC rollover, re-INVITE,
and ICE/DTLS restart only when the journal has the corresponding applied and closed
checkpoint; native proof covers PCMA as well as PCMU. Non-IPv4 media, codecs outside
G.711 PT0/PT8, and broader topology/codec policy remain outside this pilot.

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
The receipt, exact inventory, and staged publication recovery make acknowledgement
and cleanup crash-safe; the staging and receipt recovery paths have dedicated proof.
`stored` tombstones prevent duplicate capture on replay and still count toward the
100-job limit until an explicitly configured retention sweep retires an eligible
terminal row. Old PID-era legacy orphans and unknown files are never inferred or
deleted automatically; operators handle them manually.

The spool is temporary but still required for the current PCAP/finalization pipeline;
S3 does not provide direct capture input. Long-term audio lives in S3. Files remain
until the trusted backend confirms verified storage; gateway state and receipts must
survive restart. S3 lifecycle policy must preserve objects for the promised customer
retention period.

## Durable media observation guard

When managed recording is enabled, Kamailio journals INVITE/UPDATE SDP handling on
loopback port 8882 using the existing server bearer token. The private routes are
`/v1/call-events/media/begin`, `/complete` and `/close` under that same prefix.
Begin persists a pending revision before RTPengine mutation; complete marks it
applied or failed. Closure records the final revision count and sticky uncertainty.
These routes are absent when recording is disabled and reject browser Origin.

The journal stores only bounded sanitized metadata and an SDP SHA-256, never raw
SDP or ICE secrets. Each call permits at most 128 revisions. Every begin represents
a mutation, so duplicate begin is unsafe even when the payload is identical;
concurrent collisions cannot be mistaken for a stable checkpoint. Evidence follows
the existing acknowledged terminal-call retention boundary.

The production capture worker requires an open contiguous applied checkpoint
before and after NG start, and the identical checkpoint with safe closure before
finalization. Missing/failed/changed/late evidence refuses a recording. ACK with SDP
sets uncertainty; PRACK retains the existing managed-route rejection. SIP routing
continues if the journal is unavailable. Observation writes use the existing bounded
HTTP timeout, so outage may add signaling latency while refusing recording.

The guard does not broaden the pilot beyond the selected capture mode. The native
subscription proofs cover exact source-leg mapping through port/SSRC rollover,
re-INVITE, real ICE/DTLS restart, and PCMA; the default PCAP guard remains
stable-media-only. CI runs the source-leg mapping, native lifecycle, and capacity
proofs against the already built isolated media-proof image.
