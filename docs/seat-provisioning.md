# Managed seat provisioning

Task 09 adds an opt-in control service to the existing gateway. `SEAT_MODE=disabled`
remains the default. `local` retains task 08's private startup fixture; `managed`
uses durable, versioned tenant projections. Legacy SIP routing does not call this
service. Packaged DEV acceptance passed on 2026-09-11; customer rollout remains disabled.

## Operator configuration

| Setting | Contract |
| --- | --- |
| `SEAT_MODE` | Explicitly `managed` to enable runtime provisioning. |
| `SEAT_DOMAIN` | Dedicated canonical lowercase SIP realm, distinct from upstream domains. |
| `SEAT_STATE_DIR` | Required absolute path to a dedicated persistent bind mount or volume. It must be owned by the service UID, mode 0700. Container rootfs, tmpfs and ramfs are rejected. |
| `SEAT_CONTROL_TOKEN` | Dedicated random base64url token, 43–128 characters. Keep it in private server configuration; never browser config. |
| `SEAT_CONTROL_BIND` / `SEAT_CONTROL_PORT` | Default `127.0.0.1:8881`. No public port is added automatically. |
| `SEAT_CONTROL_TLS_CERT` / `SEAT_CONTROL_TLS_KEY` | Required when binding outside `127.0.0.1`. Native TLS 1.2+; backend verifies the certificate. |

Pass these variables explicitly through the deployment's Compose `environment`.
Prepare the persistent volume with the correct ownership/mode before starting
managed mode. Retain it when replacing the container. It contains usable upstream
credentials, revision high-water marks and technical username ownership; protect
its backups like credentials. Do not delete it as a cache or roll it back separately
from the authoritative backend. Generic Kamailio RPC is available only on the
owner-only `/run/kamailio/seat-rpc.sock`, never an HTTP route or network port.

## Control contract

`POST /v1/tenants/{gatewayTenantId}/snapshot` replaces the complete tenant projection.
`GET /v1/tenants/{gatewayTenantId}/status` returns sanitized applied state. Both require
`Authorization: Bearer …`. Requests with `Origin` are rejected. There is no browser
CORS interface, redirect or caller-selected management destination.

The request uses the exact [seat snapshot schema](./seat-routing.md):
`schemaVersion`, `revision`, `issuedAt`, `validUntil`, `domain`, `profiles`, `seats`.
Every profile and seat must belong to the URL tenant. An empty pair of arrays
withdraws all new calling authority for that tenant. Revisions are positive safe
integers; lease duration is at most 300 seconds. Body limit is 4 MiB. Seat/profile
limits remain 10,000/1,000 per snapshot.

A seat may add `callerIdPolicy` with exactly `mode`, `allowedNumbers` and
`defaultNumber`. `mode` is `assigned` or `flexible`; values use `^\\+?[0-9]{1,32}$`.
Assigned mode has at most 100 unique allowed numbers and an empty or allowed default;
flexible mode has an empty allowed list and an optional numeric default. Policy absence
retains the task 08 fixed profile `fromUser`. Browser seats keep `From` as their seat
identity and send one `X-Bitcall-Caller-ID` hint. The gateway strips client identity
headers and generates trusted P-Asserted-Identity and Remote-Party-ID from the
effective policy identity.

A profile may set `callerIdFormat: "headers"` to keep its account `fromUser`
in upstream From while sending the approved caller ID in PAI, RPID and PPI.
Omitted or `"custom"` uses the caller ID in From and PAI/RPID. Both add
`Privacy: none`. Digest username is independent of `fromUser`; the selected
format and caller ID remain frozen for the existing dialog. An absent caller-ID
policy still uses the profile From without creating caller-ID headers.

This is a direct format selection, not an automatic serial retry. Same-provider
retry with unchanged Call-ID/From-tag/CSeq can trigger SIP merged-request rejection;
no unverified CSeq manipulation is used. Legacy transparent routing is unchanged.
Upgrade the gateway before sending this optional field from the backend. The
webphone setting is trusted `tenant.seatRouting.callerIdFormat`; omission preserves
the older snapshot shape. Check the applied snapshot revision after changing it.
The saved `smoke_caller_id_formats.py` scenario covers both wire formats, upstream
authentication, dialog continuity, CDR identity and terminal rejection in CI.

Successful response:

```json
{"status":"applied","tenantId":"t_…","revision":7,"contentSha256":"…","validUntil":1800000300}
```

The hash is SHA-256 of UTF-8 JSON with recursively sorted object keys, unchanged
array order, no insignificant whitespace and unescaped Unicode. A duplicate
revision with the identical hash is idempotent. Older revisions or conflicting
contents return `409 REVISION_CONFLICT`; expired leases return
`409 SNAPSHOT_EXPIRED`; attempting to reassign a technical username returns
`409 SEAT_IDENTITY_CONFLICT`. Status can also be `pending` or `expired`. Responses
never contain credentials or seat/profile payloads.

## Atomicity, recovery and active calls

1. Persist accepted revision, hash, snapshot and username ownership in one SQLite
   transaction with full synchronous WAL durability. A file lock permits one writer.
2. Stage generation-prefixed htable entries for that tenant through private RPC.
3. Write its ready marker, then switch one tenant pointer. SIP authorization reads
   that pointer once and obtains all policy/credentials from the same generation.
4. Read back pointer/ready, persist applied state, then acknowledge.

A crash before the switch leaves the previous generation active. A crash after the
switch can lose the acknowledgement; retry/reconciliation completes it safely.
Reconciliation runs every two seconds and restores only unexpired accepted state
after a Kamailio restart. Accepted revisions and username ownership outlive leases.
Generation htables expire after ten minutes, beyond the five-minute admission
lease, bounding old in-memory generations. They are not the durable authority.

Suspension/rotation affects new REGISTERs and initial INVITEs after application.
An existing call retains its upstream identity and credentials in its dialog;
BYE and in-dialog handling do not depend on the latest admission lease. If a
provider invalidates an old password immediately, a challenged re-INVITE may fail;
that failure must not delete the established media session. Whole-call forced
termination is outside this contract.

Backend outage stops renewals: new seat admissions fail within five minutes of the
last issued lease. Legacy routing continues independently. Neither the helper nor
the backend may silently renumber stale policy to override a newer gateway revision;
divergent state requires explicit operator reconciliation.

## Validation

```sh
python3 -m unittest discover -s docker/seat -p 'test_*.py'
docker build -t bitcall-gateway:seat-development docker
python3 docker/healthcheck/smoke_seat_routing.py --image bitcall-gateway:seat-development
python3 docker/healthcheck/seat_dialog_fixture.py --image bitcall-gateway:seat-development
python3 docker/healthcheck/smoke_seat_routing.py --image bitcall-gateway:seat-development --managed
python3 docker/healthcheck/smoke_register_query.py --image bitcall-gateway:seat-development
```

The packaged fixtures use disposable containers without external networking,
synthetic credentials and container-owned private state. They do not contact an
upstream carrier. Remaining live provider/audio acceptance is tracked in task 08.

## DEV evidence — 2026-09-11

Candidate `bitcall-gateway-dev:task09-20260911`
(`sha256:1c15fe3e939480d11c9e2b51163f01778fb485f540fd7300097908551f23cd04`)
passed the six managed WSS scenarios: private control authentication and canonical
acknowledgements, password/HA1 upstream profiles, revocation, unaffected seats,
credential rotation and expired-lease denial. A disposable persistent-volume probe
verified helper-process and full-container restart reconciliation, identical retry
and same-revision conflict rejection. Nine provisioning unit/HTTP checks passed.

The managed htable initializer uses an explicit `return;`: Kamailio 5.7 rejects an
empty module-init route. These checks used isolated fixtures, not customer activation.
Legacy coexistence and actual provider/media results are recorded in the webphone
repository's task 08 verification record. The existing backend-to-browser handoff
has its own task 09 acceptance record there.

## Managed call-event journal (Task 11 foundation)

`SEAT_CALL_EVENTS=1` is intended only for managed seat mode with the existing
private durable state mount. It keeps an independent SQLite WAL journal beside,
but separate from, snapshot projection state. The helper exposes a loopback-only
append listener on `127.0.0.1:8882`; Kamailio admission must receive its durable
acknowledgement before forwarding a new initial call. Existing dialogs continue
when journal delivery later becomes unavailable.

The external control bearer can read one projected tenant at a time with
`GET /v1/tenants/t_<hash>/call-events?after=<sequence>&limit=<1..100>` and ack
only durable backend persistence with `POST .../call-events/ack` and
`{"throughSequence": n}`. Events are ordered by a gateway-durable global
sequence and are replay-safe. The journal stores only gateway-attributed IDs,
call timing, destination, caller-ID decision, SIP outcome and normalized
termination evidence; it never stores credentials or raw SIP headers. Call
matching to Sippy/PSTN and production retention policy remain deferred.

The event feature defaults off. It requires projected tenant/seat IDs (`t_`/`s_`
followed by 64 lowercase hexadecimal characters), as sent by the webphone backend.
The existing SIP-worker HTTP timeout remains two seconds; the append target is
local, never the remote backend. A failed admission returns 503; failed lifecycle
appends log a fixed diagnostic without exposing call payloads or credentials.

The queue holds at most 10,000 unacknowledged events and reserves the last 100
slots for terminal observations. Admission and nonterminal appends stop at 9,900.
`GET /v1/call-events/health` on the existing authenticated control surface reports
pending count, capacity and readiness. Acknowledged terminal evidence stays for
seven days before compaction; repeated acknowledgements do not extend that time.
Unacknowledged evidence is never removed by this compaction.

The private dialog inventory reconciles orphaned calls after a ten-second grace
period. Missing dialogs produce uncertain evidence, never an invented exact end.
Unknown, unavailable or truncated inventories cannot declare calls ended. Database
and backup sizing, retention policy and alerting remain production rollout gates.

The packaged managed fixture verifies two answered calls with assigned/flexible
caller IDs and password/HA1 upstream auth, plus ringing/busy/rejected/no-answer
events. Its optional export joins directly to the backend validation script:

```sh
python3 docker/healthcheck/smoke_seat_routing.py --image bitcall-gateway:seat-development --managed --call-events --events-output /tmp/call-events.json
```

On 2026-09-11 the Task 11 DEV candidate passed this fixture (15 events, five calls),
active-dialog RPC inspection and 28 focused gateway tests. Customer activation
stays disabled. The webphone repository records the matching backend acceptance.

A late answer after a failed INVITE keeps the journal open until an observed end.
The same applies when failure arrives after answer; losing that dialog later marks
uncertainty instead of leaving an indefinitely active record.
