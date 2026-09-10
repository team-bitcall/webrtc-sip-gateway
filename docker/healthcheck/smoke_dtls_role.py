#!/usr/bin/env python3
"""Packaged-route regression: WebRTC DTLS role before and after SIP answer.

No published ports or external network. This proves role selection, not audio.
"""
import argparse
import subprocess
import uuid

PROBE = r'''
import json, re, socket, time, uuid

def ng(payload):
    cookie = uuid.uuid4().hex.encode()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.sendto(cookie + b" " + json.dumps(payload).encode(), ("127.0.0.1", 2223))
        raw = s.recv(65535)
    got, body = raw.split(b" ", 1)
    assert got == cookie
    response = json.loads(body)
    assert response.get("result") in ("ok", "pong"), response
    return response

for _ in range(30):
    try:
        ng({"command": "ping"})
        break
    except (TimeoutError, OSError):
        time.sleep(.2)
else:
    raise RuntimeError("RTPengine was not ready")

browser = "\r\n".join([
    "v=0", "o=- 100 1 IN IP4 127.0.0.1", "s=role-test", "t=0 0",
    "m=audio 40000 UDP/TLS/RTP/SAVPF 0", "c=IN IP4 127.0.0.1",
    "a=rtpmap:0 PCMU/8000", "a=sendrecv", "a=rtcp-mux", "a=setup:actpass",
    "a=fingerprint:sha-256 " + ":".join(["AA"] * 32),
    "a=ice-ufrag:abcd", "a=ice-pwd:abcdefghijklmnopqrstuvwxyz012345",
    "a=candidate:1 1 UDP 2130706431 127.0.0.1 40000 typ host", ""
])
sip = "\r\n".join([
    "v=0", "o=- 200 1 IN IP4 127.0.0.1", "s=role-test", "t=0 0",
    "m=audio 40002 RTP/AVP 0", "c=IN IP4 127.0.0.1",
    "a=rtpmap:0 PCMU/8000", "a=sendrecv", ""
])

def role(call):
    response = ng({"command": "query", "call-id": call})
    media = response["tags"]["browser"]["medias"][0]
    return [flag for flag in media.get("flags", []) if "DTLS" in flag]

# Read the routes baked into this image, so removing the routing fix fails CI.
with open("/etc/kamailio/kamailio.cfg") as config:
    route_flags = re.findall(r'\$var\(rtpflags\)\s*=\s*"([^"]+)";', config.read())
assert len(route_flags) == 2, "Expected WS-to-SIP and SIP-to-WS RTP flag assignments"

def ng_flags(raw):
    """Translate the gateway's Kamailio RTP flag vocabulary into NG keys."""
    result = {}
    for token in raw.split():
        if token == "replace-origin":
            result.setdefault("replace", []).append("origin")
        elif token == "replace-session-connection":
            result.setdefault("replace", []).append("session connection")
        elif token.startswith("rtcp-mux-"):
            result.setdefault("rtcp-mux", []).append(token[len("rtcp-mux-"):])
        elif token == "SDES-off":
            result["SDES"] = "off"
        elif token in ("RTP/AVP", "RTP/SAVPF"):
            result["transport protocol"] = token
        elif "=" in token and token.split("=", 1)[0] in ("ICE", "DTLS", "DTLS-reverse"):
            key, value = token.split("=", 1)
            result[key] = value
        else:
            raise AssertionError("Unrecognised gateway RTP flag: " + token)
    return result

call = "dtls-role-" + uuid.uuid4().hex
try:
    provider = ng({
        **ng_flags(route_flags[0]), "command": "offer", "call-id": call,
        "from-tag": "browser", "sdp": browser,
    })["sdp"]
    audio_line = next(line for line in provider.splitlines() if line.startswith("m=audio "))
    assert audio_line.split()[2] == "RTP/AVP", audio_line
    assert not any(line.startswith(("a=fingerprint:", "a=setup:", "a=crypto:"))
                   for line in provider.splitlines()), "Provider leg unexpectedly encrypted"
    before = role(call)
    assert "DTLS role passive" in before and "DTLS role active" not in before, \
        "Browser leg must be passive from initial offer, got: " + repr(before)
    answered = ng({
        **ng_flags(route_flags[1]), "command": "answer", "call-id": call,
        "from-tag": "browser", "to-tag": "sip", "sdp": sip,
    })["sdp"]
    after = role(call)
    assert "DTLS role passive" in after and "DTLS role active" not in after, repr(after)
    assert "a=setup:passive" in answered
    assert "a=fingerprint:" in answered
    browser_audio = next(line for line in answered.splitlines() if line.startswith("m=audio "))
    assert browser_audio.split()[2] == "RTP/SAVPF", browser_audio
    print(json.dumps({"offer_role": before, "answer_role": after,
                      "provider_protocol": audio_line.split()[2],
                      "browser_protocol": browser_audio.split()[2]}), flush=True)
finally:
    ng({"command": "delete", "call-id": call, "delete-delay": 0})
print("PASS packaged routes: clear RTP provider, browser DTLS passive from offer through answer")
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    name = "bitcall-dtls-role-" + uuid.uuid4().hex[:12]
    try:
        subprocess.run([
            "docker", "run", "-d", "--name", name, "--network", "none", "--read-only",
            "--tmpfs", "/tmp:rw,size=64m", "--cpus", "1", "--memory", "256m",
            "--pids-limit", "128", "--entrypoint", "/usr/bin/rtpengine", args.image,
            "--config-file=none", "--foreground", "--log-stderr", "--table=-1",
            "--interface=127.0.0.1", "--listen-ng=127.0.0.1:2223",
            "--port-min=30000", "--port-max=30199", "--num-threads=2", "--media-num-threads=0",
        ], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["docker", "exec", "-i", name, "python3", "-"],
                       input=PROBE, text=True, check=True)
    except Exception:
        subprocess.run(["docker", "logs", "--tail", "30", name])
        raise
    finally:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, check=True)


if __name__ == "__main__":
    main()
