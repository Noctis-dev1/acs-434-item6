"""Second, narrower check of the #434 item 6 evidence: the parts of fault delivery verify.py's C1 leaves out.

For every run in a campaign, from the raw response bytes alone:
  D1  the ServerHello is validly signed under the test secret and declares the configured on_decision_failure
  D2  only steps/toolCallRequest is faulted: every other method got HTTP 200
  D3  schema_invalid: the faulted allow is validly signed under the test secret
  D4  wrong_signature: the faulted allow verifies under the other secret, fails under the test secret, and uses
      the same key_id as a valid reply

Usage: check_delivery.py <campaign_dir>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

import rfc8785

TEST_SECRET = "shared-test-harness-secret-not-for-production"   # the published harness test secret
WRONG_SECRET = "a-different-secret-the-adapter-does-not-hold"   # fault_guardian.WRONG_SECRET
GATE = "steps/toolCallRequest"


def session_key(secret: str, session_id: str) -> bytes:
    prk = hmac.new(b"\0" * 32, secret.encode(), hashlib.sha256).digest()
    return hmac.new(prk, session_id.encode() + b"\1", hashlib.sha256).digest()


def signed_ok(envelope: dict, key: bytes) -> bool | None:
    result = envelope.get("result")
    sig = result.get("signature") if isinstance(result, dict) else None
    if not sig:
        return None
    unsigned = {**envelope, "result": {k: v for k, v in result.items() if k != "signature"}}
    mac = hmac.new(key, rfc8785.dumps(unsigned), hashlib.sha256).digest()
    return hmac.compare_digest(mac, base64.b64decode(sig["value"]))


def key_id(envelope: dict) -> str | None:
    return ((envelope.get("result") or {}).get("signature") or {}).get("key_id")


def check(campaign: Path) -> list[str]:
    problems: list[str] = []
    runs = sorted(campaign.glob("*/rep*/evidence.json"))
    for path in runs:
        ev = json.loads(path.read_text())
        cfg, ex, where = ev["config"], ev["guardian_exchanges"], str(path.parent.relative_to(campaign))
        hello = next(x for x in ex if x["method"] == "handshake/hello")
        sid = hello["request"]["params"]["metadata"]["session_id"]
        hello_resp = json.loads(base64.b64decode(hello["response_raw_b64"]))
        good = session_key(TEST_SECRET, sid)
        if not signed_ok(hello_resp, good):
            problems.append(f"{where}: D1 ServerHello not validly signed")
        if hello_resp["result"].get("on_decision_failure") != cfg["on_decision_failure"]:
            problems.append(f"{where}: D1 ServerHello posture differs from the configuration")
        for x in ex:
            if x["method"] != GATE and x["response_status"] != 200:
                problems.append(f"{where}: D2 {x['method']} got HTTP {x['response_status']}")
        gate = [x for x in ex if x["method"] == GATE][0]
        if cfg["fault"] in ("schema_invalid", "wrong_signature"):
            env = json.loads(base64.b64decode(gate["response_raw_b64"]))
            if cfg["fault"] == "schema_invalid" and not signed_ok(env, good):
                problems.append(f"{where}: D3 schema_invalid allow is not validly signed")
            if cfg["fault"] == "wrong_signature":
                if not (signed_ok(env, session_key(WRONG_SECRET, sid)) and signed_ok(env, good) is False):
                    problems.append(f"{where}: D4 not signed with the other secret only")
                if key_id(env) != key_id(hello_resp):
                    problems.append(f"{where}: D4 key_id differs from a valid reply's")
    print(f"{len(runs)} runs checked, {len(problems)} problems")
    return problems


if __name__ == "__main__":
    found = check(Path(sys.argv[1]))
    for p in found:
        print(" ", p)
    print("DELIVERY CHECKED" if not found else "DELIVERY PROBLEMS")
    sys.exit(1 if found else 0)
