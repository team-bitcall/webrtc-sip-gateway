"""Fixture-only process entry point for the real private recording worker."""

import json
from pathlib import Path
import re
import sys


sys.path.insert(0, "/seat-proof")


ARTIFACT = Path("/tmp/artifacts/capture-rpc.json")
CDR_ID = re.compile(r"[0-9a-f]{32}\Z")
TENANT = re.compile(r"t_[0-9a-f]{64}\Z")


def _state():
    """Load the small synthetic RPC state without accepting oversized input."""
    try:
        with ARTIFACT.open("rb") as source:
            raw = source.read(4097)
        if len(raw) > 4096:
            raise ValueError()
        value = json.loads(raw.decode("utf-8", "strict"))
        if (not isinstance(value, dict) or set(value) != {"active", "tenant", "revision", "digest"}
                or not isinstance(value["active"], list)
                or not all(isinstance(item, str) and CDR_ID.fullmatch(item) for item in value["active"])
                or not isinstance(value["tenant"], str) or not TENANT.fullmatch(value["tenant"])
                or type(value["revision"]) is not int or value["revision"] < 1
                or value["digest"] != "a" * 64):
            raise ValueError()
        return value
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid fixture RPC state") from error


class FixtureRpc:
    """Only the read-only Kamailio RPC responses required by recording_runtime."""

    def active_cdr_ids(self):
        return set(_state()["active"])

    def get(self, table, key):
        state = _state()
        if table != "seat_meta":
            return None
        if key == state["tenant"] + "::active":
            return str(state["revision"])
        if key == state["tenant"] + "::%d::ready" % state["revision"]:
            return state["digest"]
        return None


def main():
    """Patch only Kamailio RPC, then enter the actual worker main function."""
    import provisioning

    provisioning.KamailioRpc = FixtureRpc
    import recording_runtime

    return recording_runtime.main()


if __name__ == "__main__":
    raise SystemExit(main())
