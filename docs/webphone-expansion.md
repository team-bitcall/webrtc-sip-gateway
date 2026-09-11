# Webphone expansion gateway work

Branch: `FEAT/webphone-expansion`, based on the installed 0.3.12 revision `73506e4d81ef704e029283c70d292f6bede262a1`. Use the team's `FEAT/…` branch convention.

Use an isolated development gateway. Deployment-specific addresses, secrets, overlays, and operational runbooks are maintained separately from this public repository. A Git branch switch does not deploy source changes into the pinned container.

Prepare and test changes locally before pushing this feature branch; several commits can be included in one push. Keep normal CI, image builds, package dry runs, and tag-triggered publishing workflows enabled. A branch push runs CI but does not itself publish packages or deploy the gateway. Version bumps and release tags belong to an agreed release, which can collect multiple tested commits. No release is required for this development milestone.

## Repository transfer and releases

The canonical source repository is now `team-bitcall/webrtc-sip-gateway`. Package repository metadata and image source labels use that address. The npm package stays `@bitcall/webrtc-sip-gateway`, and the image publish destination and CLI default remain `ghcr.io/bitcallio/webrtc-sip-gateway` so existing installations keep requesting the same image namespace.

Before the next release tag, verify that the transferred repository's Actions workflows can write to the existing GHCR package, and verify registry credentials available to the release jobs. GHCR package ownership does not follow a repository transfer. Restore the existing package's workflow access or plan a coordinated publisher/installer namespace migration; do not change just one side. This is a release prerequisite, not a reason to change a running gateway.

References: [npm provenance repository requirements](https://docs.npmjs.com/generating-provenance-statements/), [GitHub package permissions and repository transfers](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages).

## First change: TURN credential contract

- Retain the existing `username`, `credential`, `ttl`, and `uris` response fields; add absolute `expiresAt` in Unix seconds.
- Mark successful credential responses `private, no-store` at both the local helper and Kamailio HTTPS boundary.
- Respect explicit `TURN_MODE=none` even if a leftover secret exists. Legacy secret-only configuration still works. Reject nonpositive lifetimes without issuing already-expired credentials.
- Require GET for issuance, preserve OPTIONS preflight, and match the actual endpoint instead of arbitrary path prefixes.
- Check the helper's HTTP status explicitly: disabled returns 404; other failures return 502. Previously positive helper error statuses could be reported as successful HTTP 200 by Kamailio.
- Keep existing gateway API-token and Origin enforcement. The local helper remains loopback-only. The webphone backend, not the browser, should hold the gateway API token.

The separate webphone repository now has a server-side contract client and tests. The browser refresh flow and coturn development deployment remain pending. This commit does not switch a runtime ICE list or enable relay service.

## Verification

```sh
python3 -m unittest discover -s docker/healthcheck -p 'test_*.py'
python3 docker/healthcheck/smoke_turn_runtime.py --image <installed-gateway-image>
python3 docker/healthcheck/smoke_register_query.py --image <installed-gateway-image> --source-overlay
python3 docker/healthcheck/smoke_uac_auth.py --image <installed-gateway-image>
python3 docker/healthcheck/smoke_dtls_role.py --image <new-gateway-image>
cd cli
npm run lint
npm test
```

The runtime test checks the image's packaged files in disposable containers with no external network and no published ports. Add `--source-overlay` only when deliberately testing checkout changes over an older baseline image. It uses generated test certificates and non-production credentials. It verifies status, expiry, no-store headers, and authentication/method/path/Origin guards against real Kamailio. The test overrides the packaged RTPengine interface config because a network-none container only has loopback; it does not change the deployed media configuration. All test containers are removed afterward.

Verified on an isolated Linux development host with a pinned 0.3.12 image on 10 September 2026: enabled helper 200, disabled helper 404, invalid-lifetime helper 502, and all access guards passed. The Python contract tests and existing CLI lint/three test suites passed. This is credential/control-path verification, not a TURN allocation or audio test.

The first fresh-image CI run on 10 September 2026 failed at `apt-get update`: the old Bullseye base received an expired `bullseye-security` Release file. Debian ended Bullseye LTS on 31 August 2026 ([official announcement](https://www.debian.org/News/2026/20260831)). This was independent of the repository transfer and credential changes.

## Bookworm image maintenance

The image now uses digest-pinned `kamailio:5.7.5-bookworm` and the HTTPS Bookworm RTPengine 13.5 repository. Signature and expiry checks remain enabled. The isolated build retains Kamailio 5.7.5 and installs RTPengine 13.5.1.25+bpo12, replacing the baseline's 13.5.1.2+bpo11. There is no npm version bump or release tag for this development change.

For Bookworm's OpenSSL 3, Kamailio initializes the TLS module first, enables its supported `tls_threads_mode=1` core option, and uses `--atexit=no` to avoid OpenSSL shutdown cleanup of shared memory. See the [Kamailio TLS notes](https://www.kamailio.org/docs/modules/5.7.x/modules/tls.html). SIP routing and listener ports are unchanged.

The live media check also exposed an existing DTLS role-timing issue: the browser-facing leg could begin an active handshake before the SIP answer selected passive mode. The WS-to-SIP offer now includes `DTLS-reverse=passive`, matching the existing passive answer policy from the start. The provider still uses plain RTP. This follows the [upstream explanation of the same failure](https://github.com/sipwise/rtpengine/issues/1038). An isolated regression test reads the packaged route flags and checks roles before and after the answer; it fails against the preceding image and passes against the corrected image.

CI validates the packaged image through the normal initialization path, which checks the rendered Kamailio configuration before startup. Readiness polling replaces fixed startup delays; process and listener assertions fail if RTPengine or any required socket is absent. Deployment requires successful runtime/media checks and preserves the previous pinned image for rollback.

The isolated Bookworm build passed all three credential scenarios and 24 certificate-verified TLS/WebSocket upgrades with concurrency four. Kamailio process IDs stayed stable, the credential endpoint remained functional, and graceful shutdown completed with exit zero and no detected crash signatures. Bridge/read-only startup, listener, health, ACME and process checks also passed. The corrected development call connected with a verified DTLS fingerprint and increasing packets in both directions on both legs; no DTLS error appeared. This establishes media forwarding on the tested network, not human confirmation of audible playback or TURN relay coverage.

## Contact-less upstream credential verification

An RFC 3261 binding query is a REGISTER without Contact. The gateway now relays
that request upstream before local `usrloc` save, NAT Contact handling, Path and
upstream Contact synthesis, reply rewriting, or registration-failure cleanup.
`is_present_hf("Contact")` also recognizes compact `m`, so existing normal
registrations retain their Contact rewrite and local binding behavior.

The loopback runtime regression passed all four checks against the installed
5.7.5 development image with the source overlay: compact-Contact registration,
Contact-less upstream forwarding without Contact or Expires, preservation of
the existing local binding after an upstream 403, and the next normal Contact
rewrite/restore. The corrected configuration is mounted into the existing DEV
container; the image and Kamailio version are unchanged. The container is
healthy. No production gateway, listener, release version or published image
changed.

The actual provider proof used the DEV WSS route and a backend-held credential.
Its challenge realm is `sippysoft.com`, with MD5 and no qop. Password and HA1
queries were accepted; wrong password, wrong HA1, mismatched realm, unsupported
algorithm and mismatched authorization username were rejected. Every upstream
query omitted Contact and Expires, created no database record, and made no call.
The provider response proves the exact challenged authorization identity; a
separate trusted mapping is still required for a provider-internal immutable
account ID.

The installed image contains Kamailio `uac.so`, although the production gateway
route remains a transparent SIP relay. A network-none runtime fixture proved
`uac_auth()` with plaintext and `uac_auth(1)` with HA1 both receive 200 from a
realm-challenging registrar, while a wrong secret receives 403. All authenticated
retries incremented CSeq from 1 to 2 explicitly. This capability evidence does
not add a UAC seat-authentication route; that remains later webphone expansion
work. See the [Kamailio 5.7 UAC documentation](https://www.kamailio.org/docs/modules/5.7.x/modules/uac.html#uac.f.uac_auth)
and [RFC 3261 section 10.2.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-10.2.3).

## Completion criteria for dynamic STUN/TURN

Run isolated coturn with a separate secret, explicit addresses and non-overlapping ports. Connect authorized webphone requests to the helper and refresh browser credentials before new calls. Test expired credentials, idle tabs, gateway outage, UDP/TCP/TLS allocations, and a call forced through relay with confirmed audio. Preserve custom tenant transports and the legacy widget API. Inspect the packaged RTPengine interface defaults before finalizing advertised ICE addresses.

Implement local seat authentication and per-agent call events after the media baseline is established. Recording and passive listening need their own early media proof before full UI/billing work.

References: [coturn credential scheme](https://github.com/coturn/coturn/blob/master/README.turnserver#turn-rest-api), [Kamailio 5.7 HTTP-client return codes](https://github.com/kamailio/kamailio/blob/5.7/src/modules/http_client/README).
