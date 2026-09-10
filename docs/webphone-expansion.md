# Webphone expansion gateway work

Branch: `FEAT/webphone-expansion`, based on the installed 0.3.12 revision `73506e4d81ef704e029283c70d292f6bede262a1`. Use the team's `FEAT/…` branch convention.

Use an isolated development gateway. Deployment-specific addresses, secrets, overlays, and operational runbooks are maintained separately from this public repository. A Git branch switch does not deploy source changes into the pinned container.

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
cd cli
npm run lint
npm test
```

The runtime test mounts the changed source into disposable containers with no external network and no published ports. It uses generated test certificates and non-production credentials. It verifies status, expiry, no-store headers, and authentication/method/path/Origin guards against real Kamailio. The test overrides the packaged RTPengine interface config because a network-none container only has loopback; it does not change the deployed media configuration. All test containers are removed afterward.

Verified on an isolated Linux development host with a pinned 0.3.12 image on 10 September 2026: enabled helper 200, disabled helper 404, invalid-lifetime helper 502, and all access guards passed. The Python contract tests and existing CLI lint/three test suites passed. This is credential/control-path verification, not a TURN allocation or audio test.

## Completion criteria for dynamic STUN/TURN

Run isolated coturn with a separate secret, explicit addresses and non-overlapping ports. Connect authorized webphone requests to the helper and refresh browser credentials before new calls. Test expired credentials, idle tabs, gateway outage, UDP/TCP/TLS allocations, and a call forced through relay with confirmed audio. Preserve custom tenant transports and the legacy widget API. Inspect the packaged RTPengine interface defaults before finalizing advertised ICE addresses.

Implement local seat authentication and per-agent call events after the media baseline is established. Recording and passive listening need their own early media proof before full UI/billing work.

References: [coturn credential scheme](https://github.com/coturn/coturn/blob/master/README.turnserver#turn-rest-api), [Kamailio 5.7 HTTP-client return codes](https://github.com/kamailio/kamailio/blob/5.7/src/modules/http_client/README).
