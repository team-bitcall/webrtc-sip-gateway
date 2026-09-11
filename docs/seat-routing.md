# Local seat routing — development foundation

Task 08 adds an opt-in route to the existing transparent gateway. It is disabled
by default. It does not provision customers, expose a browser management API,
register shared accounts upstream, or replace the existing routing mode.

## Configuration boundary

`SEAT_DOMAIN` reserves a dedicated SIP domain. The gateway rejects that domain
when seat mode is disabled, including equivalent uppercase and trailing-dot URI
hosts. `SEAT_MODE=local` additionally requires `SEAT_SNAPSHOT_FILE` (default
`/etc/bitcall/seats.json`). The WSS host and certificate remain the gateway's
existing `DOMAIN`; they are independent of the seat SIP realm.

Only an explicitly enabled local route loads the auth, htable and UAC modules or
reads the snapshot. The startup compiler validates the complete snapshot before
writing a private include in `/run/kamailio`. No SIP request calls the webphone
backend. Legacy registration and provider selection remain independent.

The snapshot is a secret-bearing server projection. Supply it as a regular
owner-only file in a protected secrets mount; never commit it, return it to a
browser, or include its contents in diagnostics. The generated include resides
on the container's existing `/run` tmpfs. Hex encoding prevents configuration
interpolation; it is not encryption.

## Snapshot version 1

The strict JSON schema is enforced by `docker/seat/compile_snapshot.py`:

- Root: `schemaVersion: 1`, positive `revision`, Unix-second `issuedAt` and
  `validUntil`, canonical lowercase `domain`, `profiles`, `seats`.
- Profiles: `id`, `tenantId`, `enabled`, `username`, explicit digest `realm`,
  `requestDomain`, `outboundProxy`, `credential: {kind, value}`, `fromUser`.
  Credential kind is `password` or MD5 `ha1`. The current supported realm syntax
  is a lowercase DNS name, matching the proven provider contract.
- Seats: `id`, `tenantId`, globally unique `username` within the realm,
  `profileId`, `enabled`, MD5 `ha1` for `username:seat-domain:seat-password`.
- References must stay within one tenant. Duplicate keys, unknown fields,
  duplicate identities, invalid URI/credential values and permissive input-file
  permissions are rejected. Maximum input size is 4 MiB, with 10,000 seats and
  1,000 profiles; these bounds are parser limits, not tested call capacity.
- `outboundProxy` is `sip:host:port;transport=udp|tcp|tls`. Its host and
  `requestDomain` must differ from the seat domain. Request-URI, proxy transport,
  authorization username and fixed From user are separate server-owned values.

The lease lasts at most five minutes and is checked for every registration and
new call. Missing, disabled, expired or cross-tenant state denies admission.
Teardown remains available after lease expiry. Revision is metadata at this
checkpoint; durable monotonic revision enforcement, atomic live replacement,
reconciliation and revocation delivery belong to task 09. Restarting with a
snapshot is not a substitute for that provisioning protocol.

## SIP behavior

REGISTER and initial INVITE each require local seat authentication over the
gateway's WebSocket transport. Registrations use a separate `seat_location`
table. Outbound initial requests must target the seat realm; the gateway
constructs the provider destination and From identity from the trusted profile.
Caller-ID selection awaits task 10.

Initial calls carry internal seat, tenant, profile and browser connection
context. Sequential seat requests must match the known dialog and its browser
connection or transaction-observed provider peer; the legacy alias fallback is
not used to admit unknown seat dialogs. Browser hints and private CSeq helper
headers are stripped before forwarding.

Provider 401/407 authentication uses an explicit realm and one retry. Kamailio's
dialog module tracks the downstream CSeq offset and corrects responses;
configuration never hand-edits CSeq. From restoration uses dialog state. A
rejected re-INVITE must not delete the established media session.

References: [Kamailio 5.7 UAC](https://www.kamailio.org/docs/modules/5.7.x/modules/uac.html),
[dialog CSeq tracking](https://www.kamailio.org/docs/modules/5.7.x/modules/dialog.html#dialog.p.track_cseq_updates),
[local digest authentication](https://www.kamailio.org/docs/modules/5.7.x/modules/auth.html#auth.f.pv_auth_check).

## Prepared verification and remaining gates

```sh
python3 -m unittest discover -s docker/seat -p 'test_*.py'
python3 docker/healthcheck/smoke_seat_routing.py --image <gateway-image>
python3 docker/healthcheck/smoke_register_query.py --image <gateway-image>
```

Use `--source-overlay` only when intentionally testing checkout files over an
older image. These fixtures use disposable network-none containers, local
provider simulations and fixture credentials. They publish no ports and remove
their own containers afterward. CI also runs them against the built image.

The current wire evidence covers local admission/denial, two seats sharing one
provider identity, password/HA1, 407 with qop and 401 without qop, initial retry
CSeq translation, browser ACK/BYE, header stripping and unchanged legacy
registration/query behavior. It does not prove a live seat call's media,
CANCEL races, rejected/remote re-INVITEs, remote BYE, snapshot expiry during a
call, replay/out-of-order provisioning, or the complete release matrix. Keep
customer seat activation disabled until those task 08/09 gates pass.
