# webrtc-sip-gateway

[Bitcall](https://bitcall.io) WebRTC-to-SIP gateway repository.

## Components

- `docker/`: Gateway image (Kamailio + rtpengine + healthcheck responder)
- `cli/`: Linux npm CLI `@bitcall/webrtc-sip-gateway`
- `.github/workflows/`: CI

## Latest behavior updates

- Kamailio config is rendered at container init, so `#!substdef` values use live
  environment values from `.env` (domain, SIP transport/port, origin allow value).
- Kamailio listeners now advertise `GATEWAY_DOMAIN` on WSS/SIP sockets, so
  Record-Route, Path, and Via headers use the public domain (not `0.0.0.0`).
- `init` and `reconfigure` now stop the current stack before preflight checks
  to avoid false port-conflict failures on `:5060`.
- Docker image includes `sngrep` and `tcpdump` for SIP diagnostics.
- CLI includes `bitcall-gateway sip-trace` for live SIP tracing via `sngrep`
  (with compatibility handling for legacy `--sip-trace` usage).
- `bitcall-gateway update` now recreates containers after pull so newly pulled
  image layers are actually applied to running services.
- `bitcall-gateway update` now also renews anonymous volumes so image-shipped
  Kamailio config updates are not masked by stale `/etc/kamailio` volume data.
- CLI auto-migrates legacy compose files by removing the stale `/etc/kamailio`
  volume mount that can override image-shipped Kamailio config.
- Fixed nftables media firewall rule generation for IPv6 media-block mode
  (valid nft port-range syntax + action ordering).
- Media firewall state detection now checks both nft and ip6tables markers to
  avoid false "disabled" status when legacy ip6tables rules are active.
- `TURN_MODE=coturn` now writes a compose stack with a dedicated coturn service.
- In-dialog handling is hardened: if upstream sends in-dialog requests
  (including 2xx ACK) with broken/missing route-set, gateway attempts
  alias/usrloc fallback before returning 404.

## End-user install (VPS)

```bash
sudo apt-get update && sudo apt-get install -y curl ca-certificates
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm i -g @bitcall/webrtc-sip-gateway
sudo bitcall-gateway init
```

Host requirement:
- Install Docker Engine from official apt repos (`docker-ce` + `docker compose` plugin).
- Snap `docker-compose` is not supported (it cannot access `/opt/bitcall-gateway`).

Default `init` behavior is production profile with universal routing:
- `BITCALL_ENV=production`
- `ROUTING_MODE=universal`
- `ALLOWED_SIP_DOMAINS=""` (any provider domains)
- `WEBPHONE_ORIGIN="*"` (any origin)
- `SIP_TRUSTED_IPS=""` (any source IPs)

Use `sudo bitcall-gateway init --advanced` for full security/provider controls.
Use `sudo bitcall-gateway init --dev` for local testing only.
Use `--verbose` to stream installer command output; default output is concise
and full command logs are written to `/var/log/bitcall-gateway-install.log`.

Default media behavior keeps host IPv6 enabled but blocks IPv6 traffic for media
ports only (RTP/TURN) using nftables or ip6tables rules with marker:
`bitcall-gateway media ipv6 block`.
Backend selection: prefer `nftables` on non-UFW hosts; use `ip6tables` when UFW
is active to avoid ruleset conflicts.

After setup, manage with:

```bash
sudo bitcall-gateway status
sudo bitcall-gateway logs -f
sudo bitcall-gateway sip-trace
sudo bitcall-gateway restart
sudo bitcall-gateway pause
sudo bitcall-gateway resume
sudo bitcall-gateway enable
sudo bitcall-gateway disable
sudo bitcall-gateway reconfigure
sudo bitcall-gateway media status
sudo bitcall-gateway media ipv4-only on
sudo bitcall-gateway media ipv4-only off
```

## Developer quickstart

```bash
npm --prefix cli install
npm --prefix cli run lint
npm --prefix cli test
docker build -t webrtc-sip-gateway:test ./docker
```

## Manual VPS verification (post-init)

1. Systemd and container state

```bash
sudo systemctl status bitcall-gateway --no-pager
sudo docker ps --filter name=bitcall-gateway
```

2. TURN credentials endpoint (if TURN enabled)

```bash
curl -k --resolve "$(grep '^DOMAIN=' /opt/bitcall-gateway/.env | cut -d= -f2):443:127.0.0.1" \
  "https://$(grep '^DOMAIN=' /opt/bitcall-gateway/.env | cut -d= -f2)/turn-credentials"
```

3. WebSocket handshake should return `101 Switching Protocols`

```bash
DOMAIN="$(grep '^DOMAIN=' /opt/bitcall-gateway/.env | cut -d= -f2)"
curl -k -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Protocol: sip" \
  "https://${DOMAIN}/" | head -n 30
```

4. SIP listeners and service

```bash
sudo ss -ltnup | grep -E ':(443|5060|5061)\b'
sudo systemctl is-enabled bitcall-gateway
```

5. Confirm listeners advertise public domain in SIP routing headers

Capture an INVITE and verify `Record-Route`/`Path` use your gateway domain
instead of `0.0.0.0`.

## Release operations

Docker image publish is automated on git tag push (`v*`) via `.github/workflows/publish-image.yml`.
NPM package publish is automated on git tag push (`v*`) via `.github/workflows/publish-npm.yml`.

Before creating a tag:
1. Test on a fresh VPS with `bitcall-gateway init`.
2. Confirm `bitcall-gateway status` shows `Media IPv4-only: enabled`.
3. Confirm IPv6 media drop rules exist (`nft list ruleset` or `ip6tables-save`).
4. Place a real call and verify audio both directions.

```bash
# 1) bump cli/package.json version
# 2) commit
# 3) tag vX.Y.Z
# 4) push main + tags
git push origin main --tags
```
