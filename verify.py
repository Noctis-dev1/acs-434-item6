"""Independent verifier for the #434 item 6 campaign.

Re-derives every result from the raw evidence the runner stored, without importing the runner, the
fault Guardian or the ACS adapter code. Signatures are rechecked with stdlib HMAC/HKDF over RFC 8785
canonical bytes (the rfc8785 package), so the adapter's own verifier never vouches for itself.

Checks, all of which must hold for VERIFIED:
  C1  the fault was delivered as specified, read from the raw response bytes
  C2  three independent signals agree on whether the tool ran: the probe file, a toolCallResult sent to
      the Guardian, and a non-error tool_result echoed back to the model
  C3  §6.4: every run with a decision failure records an audit event for the gate, under either posture;
      the control records none
  C4  §6.4: sessionEnd reports summary.decision_failures with exactly one failure in fault runs, none in controls
  C5  the tool ran exactly when the audit event says the posture was fail_open
  C6  every rep of a configuration produced the same outcome
  C7  the manifest pins clean commits for ACS and the harness

Usage: verify.py [campaign_dir]      (default: the newest runs/campaign-*)
       verify.py --selftest [campaign_dir]   (mutates evidence in memory; each mutation must be caught)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import rfc8785

HERE = Path(__file__).resolve().parent
TEST_SECRET = "shared-test-harness-secret-not-for-production"   # the published harness test secret
GATE = "steps/toolCallRequest"
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def hkdf_key(secret: bytes, session_id: str) -> bytes:
    prk = hmac.new(b"\x00" * 32, secret, hashlib.sha256).digest()
    return hmac.new(prk, session_id.encode() + b"\x01", hashlib.sha256).digest()


def sig_valid(envelope: dict, key: bytes) -> bool:
    ckey = "error" if "error" in envelope else "result"
    container = envelope.get(ckey)
    if not isinstance(container, dict) or not isinstance(container.get("signature"), dict):
        return False
    value = container["signature"].get("value", "")
    stripped = {**envelope, ckey: {k: v for k, v in container.items() if k != "signature"}}
    want = hmac.new(key, rfc8785.dumps(stripped), hashlib.sha256).digest()
    try:
        return hmac.compare_digest(want, base64.b64decode(value, validate=True))
    except ValueError:
        return False


def fault_delivered(fault: str, ex: dict) -> tuple[bool, str]:
    raw = base64.b64decode(ex["response_raw_b64"])
    req = ex["request"]
    sid = req["params"]["metadata"]["session_id"]
    key = hkdf_key(TEST_SECRET.encode(), sid)
    if fault == "http_500":
        return ex["response_status"] == 500 and not raw.lstrip().startswith(b"{"), "HTTP 500, non-JSON-RPC body"
    if fault == "non_json":
        try:
            json.loads(raw)
            return False, "body parsed as JSON"
        except ValueError:
            return ex["response_status"] == 200, "HTTP 200, body is not JSON"
    resp = json.loads(raw)
    result = resp.get("result") or {}
    bound = result.get("request_id") == req["params"]["request_id"] and resp.get("id") == req.get("id")
    hex_ok = bool(HEX64.match(str(result.get("chain_hash", ""))))
    signed_ok = sig_valid(resp, key)
    allow = result.get("decision") == "allow"
    checks = {
        "none":             allow and bound and hex_ok and signed_ok,
        "schema_invalid":   allow and bound and not hex_ok and signed_ok,
        "wrong_request_id": allow and not bound and hex_ok and signed_ok,
        "unsigned":         allow and bound and hex_ok and "signature" not in result,
        "wrong_signature":  allow and bound and hex_ok and "signature" in result and not signed_ok,
    }
    return checks[fault], f"allow={allow} bound={bound} chain_hash_hex={hex_ok} signature_valid={signed_ok}"


def derive(ev: dict) -> dict:
    cfg = ev["config"]
    ex = ev["guardian_exchanges"]
    gates = [x for x in ex if x.get("method") == GATE]
    problems = []
    if len(gates) != 1:
        problems.append(f"expected one {GATE}, saw {len(gates)}")
        delivered, how = False, "no single gate exchange"
    else:
        delivered, how = fault_delivered(cfg["fault"], gates[0])
    if not delivered:
        problems.append(f"C1 fault not delivered as specified: {how}")

    probe = bool(ev["probe"]["exists"])
    sent_result = any(x.get("method") == "steps/toolCallResult" for x in ex)
    tool_results = [t for m in ev["model_log"] for t in m.get("tool_results", [])]
    model_ok = bool(tool_results) and not tool_results[-1]["is_error"]
    if not (probe == sent_result == model_ok):
        problems.append(f"C2 signals disagree: probe={probe} toolCallResult={sent_result} model_tool_result_ok={model_ok}")

    gate_audits = [a for a in ev["audit_events"] if a.get("hook") == "PreToolUse" and "acs_audit_event" in a]
    is_fault = cfg["fault"] != "none"
    if is_fault and len(gate_audits) != 1:
        problems.append(f"C3 expected one gate audit event, saw {len(gate_audits)}")
    if not is_fault and ev["audit_events"]:
        problems.append(f"C3 control recorded audit events: {ev['audit_events']}")

    ends = [x["request"] for x in ex if x.get("method") == "steps/sessionEnd"]
    summary = ((ends[0]["params"].get("payload") or {}).get("summary") or {}) if ends else None
    failures = (summary or {}).get("decision_failures")
    total = sum(failures.values()) if isinstance(failures, dict) else None
    if total != (1 if is_fault else 0):
        problems.append(f"C4 summary.decision_failures={failures!r}")

    audit = gate_audits[0] if gate_audits else {}
    posture = audit.get("posture")
    if is_fault and (posture == "fail_open") != probe:
        problems.append(f"C5 tool ran={probe} but audit posture={posture}")
    return {
        "tool_ran": probe,
        "audit_event": audit.get("acs_audit_event"),
        "cause": audit.get("cause"),
        "failure_class": audit.get("failure_class"),
        "posture": posture,
        "decision_failures": failures,
        "agent_saw": (tool_results[-1]["content"][:90] if tool_results and tool_results[-1]["is_error"] else None),
        "problems": problems,
    }


def load(campaign: Path) -> tuple[dict, list[dict]]:
    manifest = json.loads((campaign / "manifest.json").read_text())
    evs = [json.loads(p.read_text()) for p in sorted(campaign.glob("*/rep*/evidence.json"))]
    return manifest, evs


def verify(manifest: dict, evs: list[dict], *, quiet: bool = False) -> tuple[bool, list[dict]]:
    problems = []
    if manifest.get("acs_dirty") or manifest.get("harness_dirty"):
        problems.append("C7 manifest records a dirty tree")
    by_cfg = defaultdict(list)
    for ev in evs:
        d = derive(ev)
        c = ev["config"]
        key = (c["fault"], c["on_decision_failure"], c["wiring"])
        by_cfg[key].append(d)
        problems += [f"{key} rep{c.get('rep')}: {p}" for p in d["problems"]]
    rows = []
    for key, ds in sorted(by_cfg.items()):
        outcomes = {json.dumps({k: d[k] for k in ("tool_ran", "audit_event", "cause", "posture")}, sort_keys=True) for d in ds}
        if len(outcomes) != 1:
            problems.append(f"C6 {key}: reps disagree: {outcomes}")
        d = ds[0]
        rows.append({"fault": key[0], "guardian_on_decision_failure": key[1], "wiring": key[2], "reps": len(ds),
                     "tool_ran": sum(x["tool_ran"] for x in ds), "audit_event": d["audit_event"], "cause": d["cause"],
                     "failure_class": d["failure_class"], "posture": d["posture"],
                     "decision_failures": d["decision_failures"], "agent_saw": d["agent_saw"]})
    if not quiet:
        print(f"{'fault':17} {'guardian':8} {'wiring':14} ran   {'audit event':30} {'cause':26} posture")
        for r in rows:
            print(f"{r['fault']:17} {r['guardian_on_decision_failure']:8} {r['wiring']:14} "
                  f"{r['tool_ran']}/{r['reps']:<3} {str(r['audit_event']):30} {str(r['cause']):26} {r['posture']}")
        for p in problems:
            print("PROBLEM:", p)
    return not problems, rows


def selftest(manifest: dict, evs: list[dict]) -> bool:
    def first(fault, wiring="all_fail_open", posture="proceed"):
        for i, ev in enumerate(evs):
            c = ev["config"]
            if (c["fault"], c["on_decision_failure"], c["wiring"]) == (fault, posture, wiring):
                return i
        raise LookupError(fault)

    def mutate(name, fn):
        m, e = copy.deepcopy(manifest), copy.deepcopy(evs)
        fn(m, e)
        ok, _ = verify(m, e, quiet=True)
        print(f"  {'caught' if not ok else 'MISSED'}: {name}")
        return not ok

    def flip_probe(m, e):
        e[first("http_500", "default")]["probe"]["exists"] = True

    def drop_audit(m, e):
        e[first("non_json")]["audit_events"] = []

    def real_signature(m, e):
        # Re-sign the "wrong_signature" response with the correct key: it is no longer the fault it claims.
        ev = e[first("wrong_signature")]
        ex = next(x for x in ev["guardian_exchanges"] if x["method"] == GATE)
        resp = json.loads(base64.b64decode(ex["response_raw_b64"]))
        sid = ex["request"]["params"]["metadata"]["session_id"]
        stripped = {**resp, "result": {k: v for k, v in resp["result"].items() if k != "signature"}}
        val = base64.b64encode(hmac.new(hkdf_key(TEST_SECRET.encode(), sid), rfc8785.dumps(stripped),
                                        hashlib.sha256).digest()).decode()
        resp["result"]["signature"]["value"] = val
        ex["response_raw_b64"] = base64.b64encode(json.dumps(resp).encode()).decode()

    def fix_chain_hash(m, e):
        ev = e[first("schema_invalid")]
        ex = next(x for x in ev["guardian_exchanges"] if x["method"] == GATE)
        resp = json.loads(base64.b64decode(ex["response_raw_b64"]))
        resp["result"]["chain_hash"] = "0" * 64
        ex["response_raw_b64"] = base64.b64encode(json.dumps(resp).encode()).decode()

    def zero_summary(m, e):
        ev = e[first("unsigned")]
        end = next(x for x in ev["guardian_exchanges"] if x["method"] == "steps/sessionEnd")
        end["request"]["params"]["payload"]["summary"]["decision_failures"] = {}

    def one_rep_differs(m, e):
        ev = e[first("wrong_request_id")]
        ev["probe"]["exists"] = True
        ev["guardian_exchanges"].append({"method": "steps/toolCallResult"})
        ev["model_log"][-1]["tool_results"] = [{"is_error": False, "content": "File created"}]

    def dirty(m, e):
        m["harness_dirty"] = True

    results = [mutate("a blocked run reported as ran", flip_probe),
               mutate("a fail-open bypass with its audit event deleted", drop_audit),
               mutate("a 'wrong signature' that is actually valid", real_signature),
               mutate("a 'schema-invalid' allow that is actually valid", fix_chain_hash),
               mutate("a decision failure missing from summary.decision_failures", zero_summary),
               mutate("one rep that ran where the others were blocked", one_rep_differs),
               mutate("a dirty harness tree in the manifest", dirty)]
    return all(results)


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    campaigns = sorted((HERE / "evidence").glob("campaign-*")) or sorted((HERE / "runs").glob("campaign-*"))
    campaign = Path(args[0]) if args else campaigns[-1]
    manifest, evs = load(campaign)
    if "--selftest" in sys.argv:
        print(f"selftest on {campaign.name} ({len(evs)} runs):")
        ok = selftest(manifest, evs)
        print("SELFTEST PASSED" if ok else "SELFTEST FAILED")
        return 0 if ok else 1
    ok, rows = verify(manifest, evs)
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    (out / f"{campaign.name}.summary.json").write_text(json.dumps(
        {"campaign": campaign.name, "runs": len(evs), "manifest": manifest, "verified": ok, "rows": rows}, indent=1))
    print(f"{len(evs)} runs, {len(rows)} configurations")
    print("VERIFIED" if ok else "NOT VERIFIED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
