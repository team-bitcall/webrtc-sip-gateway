FROM ghcr.io/kamailio/kamailio:5.7.5-bookworm@sha256:2e109d4dc7ef395e02c8f7266e05a9356dd711309923215c93fe3e90676f48db

ARG DEBIAN_FRONTEND=noninteractive
ARG S6_OVERLAY_VERSION=3.2.0.2
ARG TARGETARCH

ENV S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
    S6_VERBOSITY=1 \
    RTPENGINE_MIN_PORT=10000 \
    RTPENGINE_MAX_PORT=10100 \
    PRIVATE_IP= \
    PUBLIC_IP= \
    DOMAIN=localhost \
    TURN_TTL=86400 \
    ACME_LISTEN_PORT=80 \
    TURN_SECRET= \
    ALLOWED_SIP_DOMAINS=

# Base runtime deps (+ minimal ops tooling required by plan/healthchecks)
# - procps: ps/pgrep checks in CI and troubleshooting
# - iproute2: PRIVATE_IP auto-detection in rtpengine run script
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
      ca-certificates curl python3 xz-utils \
      gnupg wget procps iproute2 openssl tcpdump sngrep \
  && rm -rf /var/lib/apt/lists/*

# Add RTPengine apt repo (bookworm) maintained by Kamailio community
# Repo list is published here: https://deb.kamailio.org/rtpengine.html
RUN set -eux; \
  wget -qO- https://deb.kamailio.org/kamailiodebkey.gpg \
    | gpg --dearmor -o /usr/share/keyrings/kamailio-archive.gpg; \
  echo "deb [signed-by=/usr/share/keyrings/kamailio-archive.gpg] https://deb.kamailio.org/rtpengine-mr13.5 bookworm main" \
    > /etc/apt/sources.list.d/rtpengine.list; \
  apt-get update; \
  apt-get install -y --no-install-recommends rtpengine; \
  rm -rf /var/lib/apt/lists/*

# Install s6-overlay
RUN set -eux; \
  S6_ARCH="x86_64"; \
  curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
    | tar -C / -Jxpf -; \
  curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz" \
    | tar -C / -Jxpf -

COPY kamailio/kamailio.cfg /etc/kamailio/kamailio.cfg
# The base image persists /etc/kamailio. Ship routing code outside that volume
# so an existing installation cannot mask it with an older anonymous volume.
COPY kamailio/seat-routing.cfg /opt/bitcall/seat-routing.cfg
COPY kamailio/call-events.cfg /opt/bitcall/call-events.cfg
COPY seat/compile_snapshot.py /opt/bitcall/compile_seat_snapshot.py
COPY seat/compile_snapshot.py seat/call_journal.py seat/media_control.py seat/media_watchdog.py seat/provisioning.py /opt/bitcall/seat/
COPY seat/recording_artifacts.py seat/recording_cleanup.py seat/recording_capture.py seat/recording_decode.py seat/recording_binding.py seat/recording_storage.py seat/recording_runtime.py seat/recording_transport.py /opt/bitcall/seat/
COPY kamailio/tls.cfg /etc/kamailio/tls.cfg
COPY healthcheck/healthcheck_server.py /opt/bitcall/healthcheck_server.py
COPY rootfs/ /

RUN chmod +x /etc/cont-init.d/* /etc/services.d/*/run

EXPOSE 80/tcp 5060/tcp 5060/udp 10000-10100/udp

HEALTHCHECK --interval=10s --timeout=3s --retries=6 \
  CMD sh -ec 'curl -fsS "http://127.0.0.1:${ACME_LISTEN_PORT}/.well-known/acme-challenge/healthcheck"'

ENTRYPOINT ["/init"]
