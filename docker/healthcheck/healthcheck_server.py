#!/usr/bin/env python3
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import threading
import time
from urllib.parse import parse_qs, urlparse

ACME_CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
ACME_ROOT = "/var/www/acme/.well-known/acme-challenge"
TURN_LISTEN_HOST = "127.0.0.1"
TURN_LISTEN_PORT = 8880
TURN_CREDENTIALS_PATH = "/turn-credentials"

DOMAIN = os.environ.get("DOMAIN", "localhost")
TURN_SECRET = os.environ.get("TURN_SECRET", "")
TURN_TTL = int(os.environ.get("TURN_TTL", "86400"))
TURN_UDP_PORT = int(os.environ.get("TURN_UDP_PORT", "3478"))
TURNS_TCP_PORT = int(os.environ.get("TURNS_TCP_PORT", "5349"))
ACME_LISTEN_PORT = int(os.environ.get("ACME_LISTEN_PORT", "80"))


def _write_plain(handler, status_code, body):
    payload = body.encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "text/plain; charset=utf-8")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


class AcmeHandler(http.server.BaseHTTPRequestHandler):
    def _handle_request(self, send_body):
        parsed_path = urlparse(self.path).path

        if parsed_path.startswith(ACME_CHALLENGE_PREFIX):
            token = parsed_path[len(ACME_CHALLENGE_PREFIX) :]
            if token == "healthcheck":
                if send_body:
                    _write_plain(self, 200, "ok")
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                return

            if token and "/" not in token and ".." not in token:
                challenge_path = os.path.join(ACME_ROOT, token)
                if os.path.isfile(challenge_path):
                    with open(challenge_path, "rb") as challenge_file:
                        body = challenge_file.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if send_body:
                        self.wfile.write(body)
                    return

        self.send_response(301)
        self.send_header("Location", f"https://{DOMAIN}{self.path}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._handle_request(send_body=True)

    def do_HEAD(self):
        self._handle_request(send_body=False)

    def log_message(self, _format, *_args):
        return


class TurnCredentialsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urlparse(self.path).path
        # Keep the legacy secret-only configuration working, but respect an
        # explicitly disabled relay even if a previous secret is still present.
        if (parsed_path != TURN_CREDENTIALS_PATH or not TURN_SECRET
                or os.environ.get("TURN_MODE") == "none"):
            _write_plain(self, 404, "not found")
            return

        if TURN_TTL <= 0:
            _write_plain(self, 503, "invalid TURN credential lifetime")
            return

        scope = parse_qs(urlparse(self.path).query, keep_blank_values=True).get("scope")
        if scope is not None and (len(scope) != 1 or not re.fullmatch(r"t_[a-f0-9]{64}", scope[0])):
            _write_plain(self, 400, "invalid scope")
            return
        # The public proxy accepts scoped issuance only with its backend bearer.
        # A stable member suffix keeps identity independent of token rotation.
        expires_at = int(time.time()) + TURN_TTL
        username = f"{expires_at}:{scope[0] if scope else 'webrtc'}"
        mac = hmac.new(
            TURN_SECRET.encode("utf-8"),
            username.encode("utf-8"),
            hashlib.sha1,
        ).digest()
        credential = base64.b64encode(mac).decode("ascii")
        response = {
            "username": username,
            "credential": credential,
            "ttl": TURN_TTL,
            "expiresAt": expires_at,
            "uris": [
                f"turn:{DOMAIN}:{TURN_UDP_PORT}",
                f"turn:{DOMAIN}:{TURN_UDP_PORT}?transport=tcp",
                f"turns:{DOMAIN}:{TURNS_TCP_PORT}",
            ],
        }
        payload = json.dumps(response).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "private, no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        return


def main():
    acme_server = http.server.ThreadingHTTPServer(("0.0.0.0", ACME_LISTEN_PORT), AcmeHandler)
    turn_server = http.server.ThreadingHTTPServer(
        (TURN_LISTEN_HOST, TURN_LISTEN_PORT), TurnCredentialsHandler
    )

    acme_thread = threading.Thread(target=acme_server.serve_forever, daemon=True)
    acme_thread.start()
    turn_server.serve_forever()


if __name__ == "__main__":
    main()
