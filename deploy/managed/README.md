# Managed gateway overlay

This is opt-in. It does not change the stock CLI or `dev/domo3` compose deployment.

Keep three mode-0600 files outside Git: a Compose-path env file, `GATEWAY_ENV_FILE` for existing network/TLS/STUN/TURN settings, and `MANAGED_ENV_FILE` for `SEAT_*` settings. Pin `BITCALL_GATEWAY_IMAGE` by digest and use three distinct service-owned mode-0700 durable directories. The recording spool filesystem must be bounded to 128 MiB or less.

`SEAT_MANAGED_ADMISSION_ENDPOINT` is `${WEBPHONE_ORIGIN}/api/internal/managed-call-admission`; its private `SEAT_MANAGED_ADMISSION_SECRET` is the same value as backend `MANAGED_CALL_ADMISSION_SECRET`. Keep both feature flags disabled until their dependent checks are complete.

Validate without starting anything:

```sh
node deploy/managed/validate.mjs /private/managed-gateway-compose.env
docker compose --env-file /private/managed-gateway-compose.env -f deploy/managed/compose.yaml config --quiet
```

Start only after review with `docker compose --env-file /private/managed-gateway-compose.env -f deploy/managed/compose.yaml up -d --wait`. The overlay forces `SEAT_MODE=managed` and loopback `SEAT_CONTROL_BIND=127.0.0.1`; feature flags stay private and default-disabled. Validator output is a configuration subset check, not startup or runtime acceptance. No secrets are embedded in this repository.
