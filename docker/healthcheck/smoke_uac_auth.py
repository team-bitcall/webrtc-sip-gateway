#!/usr/bin/env python3
"""Prove Kamailio UAC plaintext, HA1, realm, rejection, and CSeq behavior.

Runs a minimal Kamailio process and registrar inside one network-none
disposable container. All identities and secrets are generated for the test.
"""

import argparse
import subprocess
import uuid


IN_CONTAINER_TEST = r'''
import hashlib
import os
import re
import socket
import subprocess
import threading
import time
import uuid

REALM = "fixture.realm"
PROXY_PORT = 16061
REGISTRAR_PORT = 16060
secret = uuid.uuid4().hex
ha1 = hashlib.md5(f"ha1:{REALM}:{secret}".encode()).hexdigest()
wrong_secret = uuid.uuid4().hex

config = f"""#!KAMAILIO
debug=2
log_stderror=yes
fork=no
children=1
auto_aliases=no
listen=udp:127.0.0.1:{PROXY_PORT}
loadmodule "tm.so"
loadmodule "sl.so"
loadmodule "rr.so"
loadmodule "pv.so"
loadmodule "textops.so"
loadmodule "uac.so"
modparam("uac", "auth_realm_avp", "$avp(arealm)")
modparam("uac", "auth_username_avp", "$avp(auser)")
modparam("uac", "auth_password_avp", "$avp(apass)")

request_route {{
    if (!is_method("REGISTER")) {{
        sl_send_reply("405", "Method Not Allowed");
        exit;
    }}
    force_rport();
    $du = "sip:127.0.0.1:{REGISTRAR_PORT};transport=udp";
    t_on_failure("AUTH");
    if (!t_relay()) {{ sl_reply_error(); }}
    exit;
}}

failure_route[AUTH] {{
    if (!t_check_status("401")) {{ exit; }}
    $avp(arealm) = "";
    $avp(auser) = $fU;
    if ($fU == "plain") {{
        $avp(apass) = "{secret}";
        $var(auth_mode) = 0;
    }} else if ($fU == "ha1") {{
        $avp(apass) = "{ha1}";
        $var(auth_mode) = 1;
    }} else {{
        $avp(apass) = "{wrong_secret}";
        $var(auth_mode) = 0;
    }}
    if ($var(auth_mode) == 1) {{
        if (!uac_auth("1")) {{ exit; }}
    }} else {{
        if (!uac_auth()) {{ exit; }}
    }}
    $var(next_cseq) = $(cs{{s.int}}) + 1;
    remove_hf("CSeq");
    append_hf("CSeq: $var(next_cseq) REGISTER\\r\\n");
    t_relay();
    exit;
}}
"""
config_path = "/tmp/uac-auth-fixture.cfg"
log_path = "/tmp/uac-auth-fixture.log"
with open(config_path, "w", encoding="utf-8") as handle:
    handle.write(config)

def parse(message):
    lines = message.decode("utf-8", "replace").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers.setdefault(name.lower(), []).append(value.strip())
    return lines[0], headers

def digest_params(value):
    assert value.lower().startswith("digest "), value
    result = {}
    for match in re.finditer(r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"([^"]*)"|([^,\s]+))', value[7:]):
        result[match.group(1).lower()] = match.group(2) if match.group(2) is not None else match.group(3)
    return result

def response(request, status, reason, challenge=None):
    _, headers = parse(request)
    lines = [f"SIP/2.0 {status} {reason}"]
    lines += [f"Via: {value}" for value in headers["via"]]
    lines += [f"From: {headers['from'][0]}", f"To: {headers['to'][0]};tag=registrar",
              f"Call-ID: {headers['call-id'][0]}", f"CSeq: {headers['cseq'][0]}"]
    if challenge:
        lines.append(f'WWW-Authenticate: Digest realm="{REALM}", nonce="{challenge}", algorithm=MD5, qop="auth"')
    return "\r\n".join(lines + ["Content-Length: 0", "", ""]).encode()

observed = {name: [] for name in ("plain", "ha1", "wrong")}
registrar_errors = []

def registrar():
    nonces = {}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", REGISTRAR_PORT))
            sock.settimeout(8)
            for _ in range(6):
                request, peer = sock.recvfrom(65535)
                _, headers = parse(request)
                username = headers["from"][0].split("sip:", 1)[1].split("@", 1)[0]
                cseq = int(headers["cseq"][0].split()[0])
                observed[username].append(cseq)
                authorization = headers.get("authorization", [])
                if not authorization:
                    assert cseq == 1, (username, cseq)
                    nonce = uuid.uuid4().hex
                    nonces[headers["call-id"][0]] = nonce
                    sock.sendto(response(request, 401, "Unauthorized", nonce), peer)
                    continue
                assert cseq == 2, (username, cseq)
                params = digest_params(authorization[0])
                assert params["username"] == username
                assert params["realm"] == REALM
                assert params["uri"] == f"sip:{REALM}"
                assert params.get("qop") == "auth"
                assert params.get("nc") == "00000001"
                nonce = nonces[headers["call-id"][0]]
                assert params["nonce"] == nonce
                expected_ha1 = hashlib.md5(f"{username}:{REALM}:{secret}".encode()).hexdigest()
                ha2 = hashlib.md5(f"REGISTER:sip:{REALM}".encode()).hexdigest()
                expected = hashlib.md5(
                    f"{expected_ha1}:{nonce}:{params['nc']}:{params['cnonce']}:auth:{ha2}".encode()
                ).hexdigest()
                valid = params["response"] == expected
                sock.sendto(response(request, 200 if valid else 403,
                                     "OK" if valid else "Forbidden"), peer)
    except BaseException as exc:
        registrar_errors.append(exc)

thread = threading.Thread(target=registrar, daemon=True)
thread.start()
subprocess.check_call(["kamailio", "-c", "-f", config_path],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
log_handle = open(log_path, "w", encoding="utf-8")
process = subprocess.Popen(["kamailio", "--atexit=no", "-DD", "-E", "-f", config_path,
                            "-m", "16", "-M", "4"],
                           stdout=log_handle, stderr=subprocess.STDOUT, text=True)
try:
    time.sleep(1)
    if process.poll() is not None:
        raise RuntimeError("minimal Kamailio exited before the fixture ran")

    def transact(username):
        token = uuid.uuid4().hex
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind(("127.0.0.1", 0))
            client_port = client.getsockname()[1]
            request = "\r\n".join([
                f"REGISTER sip:{REALM} SIP/2.0",
                f"Via: SIP/2.0/UDP 127.0.0.1:{client_port};branch=z9hG4bK{token};rport",
                "Max-Forwards: 16", f"From: <sip:{username}@{REALM}>;tag={token}",
                f"To: <sip:{username}@{REALM}>", f"Call-ID: {token}@fixture.invalid",
                "CSeq: 1 REGISTER", "Content-Length: 0", "", "",
            ]).encode()
            client.settimeout(8)
            client.sendto(request, ("127.0.0.1", PROXY_PORT))
            while True:
                reply, _ = client.recvfrom(65535)
                status = int(reply.split(b" ", 2)[1])
                if status >= 200:
                    return status

    try:
        statuses = {username: transact(username) for username in ("plain", "ha1", "wrong")}
    except BaseException as exc:
        safe_errors = [f"{type(item).__name__}: {item}" for item in registrar_errors]
        log_handle.flush()
        with open(log_path, encoding="utf-8", errors="replace") as handle:
            safe_log = [line.strip() for line in handle
                        if re.search(r"\b(?:ERROR|CRITICAL)\b|failed", line, re.I)
                        and not re.search(r"Authorization|Proxy-Authorization|nonce|response=", line, re.I)]
        raise RuntimeError(
            f"UAC fixture failed; observed_cseq={observed}; registrar_errors={safe_errors}; "
            f"kamailio_errors={safe_log[-12:]}"
        ) from exc
    thread.join(timeout=2)
    assert not thread.is_alive(), "fixture registrar did not finish"
    if registrar_errors:
        raise registrar_errors[0]
    assert statuses == {"plain": 200, "ha1": 200, "wrong": 403}, statuses
    assert observed == {"plain": [1, 2], "ha1": [1, 2], "wrong": [1, 2]}, observed
    print("PASS uac_auth() plaintext accepted after realm challenge")
    print("PASS uac_auth(1) HA1 accepted after realm challenge")
    print("PASS wrong plaintext rejected and all authenticated REGISTER CSeq values incremented 1 -> 2")
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    log_handle.close()
    os.unlink(config_path)
    os.unlink(log_path)
'''


def run(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="Gateway image containing Kamailio uac.so")
    args = parser.parse_args()
    name = "bitcall-uac-auth-" + uuid.uuid4().hex[:12]
    created = False
    try:
        run("docker", "run", "-d", "--name", name, "--network", "none",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m",
            "--cpus", "1", "--memory", "256m", "--pids-limit", "128",
            "--security-opt", "no-new-privileges:true", "--entrypoint", "/bin/sh",
            args.image, "-c", "sleep 300")
        created = True
        print(run("docker", "exec", "-i", name, "python3", "-",
                  input=IN_CONTAINER_TEST, timeout=30).strip())
    except Exception:
        if created:
            print(run("docker", "logs", "--tail", "80", name,
                      stderr=subprocess.STDOUT))
        raise
    finally:
        if created:
            run("docker", "rm", "-f", name, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
