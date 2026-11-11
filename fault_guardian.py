"""A Guardian for #434 item 6 that answers every method correctly except steps/toolCallRequest, where it
misbehaves in exactly one way per run. Built on the reference harness's signing and verification
(acs.client / acs.core at the pinned commit), so every reply that is meant to be valid is valid.

Faults (applied to steps/toolCallRequest only):
  none              a correct, signed allow (control)
  schema_invalid    a signed allow whose chain_hash breaks response-envelope.json (pattern ^[0-9a-f]{64}$)
  wrong_request_id  a signed allow whose result.request_id names a different request
  non_json          HTTP 200, Content-Type application/json, a body that is not JSON
  http_500          HTTP 500 with a plain-text body (not a JSON-RPC envelope)
  unsigned          a correct allow sent without a signature
  wrong_signature   a correct allow signed with a different secret under the same key_id
"""
from __future__ import annotations

import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

from acs import client, core
from acs.testing.harness import ProgrammableGuardian, TEST_KEY_ID

FAULTS = ("none", "schema_invalid", "wrong_request_id", "non_json", "http_500", "unsigned", "wrong_signature")
GATE_METHOD = "steps/toolCallRequest"
WRONG_SECRET = "a-different-secret-the-adapter-does-not-hold"


class FaultGuardian:
    def __init__(self, *, fault: str, on_decision_failure: str, hmac_secret: str | None = None) -> None:
        if fault not in FAULTS:
            raise ValueError(f"unknown fault {fault!r}")
        if on_decision_failure not in ("proceed", "deny"):
            raise ValueError("on_decision_failure must be proceed or deny")
        self.fault = fault
        self.on_decision_failure = on_decision_failure
        self.hmac_secret = hmac_secret or ProgrammableGuardian.DEFAULT_TEST_HMAC_SECRET
        self.key_id = TEST_KEY_ID
        self.exchanges: list[dict] = []
        self.lock = threading.Lock()
        self._server = HTTPServer(("127.0.0.1", 0), self._handler_cls())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/acs"

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()

    def received(self) -> list[dict]:
        with self.lock:
            return [e["request"] for e in self.exchanges if isinstance(e.get("request"), dict)]

    # Correct results, before any fault.
    def _result(self, req: dict) -> dict:
        method = req.get("method", "")
        if method == "handshake/hello":
            offered = (req.get("params") or {}).get("payload") or {}
            return {
                "negotiated_version": "0.1.0",
                "methods_evaluated": offered.get("methods_implemented", []),
                "selected_transport": next((t for t in offered.get("transports_supported", []) if t != "stdio"), "http"),
                "signature_algorithms_supported": ["HMAC-SHA256"],
                "timeout_config": {"default_ms": 5000},
                "skew_window_ms": 300000,
                "on_decision_failure": self.on_decision_failure,
                "profiles_accepted": [p for p in offered.get("profiles_supported", []) if p == "acs-core"],
            }
        return {"type": "final", "acs_version": "0.1.0", "request_id": req["params"]["request_id"],
                "decision": "allow", "chain_hash": "0" * 64}

    def _sign(self, resp: dict, sid: str, secret: str) -> dict:
        key = core.derive_session_key(secret.encode(), sid)
        client.sign_envelope(resp, key=key, session_id=sid, key_id=self.key_id)
        return resp

    def _handler_cls(self):
        g = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                record: dict = {"request_raw_b64": base64.b64encode(raw).decode()}
                try:
                    req = json.loads(raw.decode())
                except ValueError:
                    record["request"] = None
                    self._send(400, b"bad request", "text/plain", record, fault_applied=None)
                    return
                record["request"] = req
                method = req.get("method", "")
                sid = ((req.get("params") or {}).get("metadata") or {}).get("session_id", "")
                record["request_signature_valid"] = (
                    method == "system/ping"
                    or client.verify_signature(req, key=core.derive_session_key(g.hmac_secret.encode(), sid),
                                               session_id=sid, key_id=g.key_id))
                if not record["request_signature_valid"]:
                    resp = {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32004, "message": "SIGNATURE_INVALID"}}
                    self._send(200, json.dumps(resp).encode(), "application/json", record, fault_applied=None)
                    return
                result = g._result(req)
                fault = g.fault if method == GATE_METHOD else "none"
                if fault == "non_json":
                    self._send(200, b"<html><body>upstream proxy error</body></html>", "application/json",
                               record, fault_applied=fault)
                    return
                if fault == "http_500":
                    self._send(500, b"Internal Server Error", "text/plain", record, fault_applied=fault)
                    return
                if fault == "schema_invalid":
                    result = {**result, "chain_hash": "zz-not-a-sha256-hex-digest"}
                if fault == "wrong_request_id":
                    result = {**result, "request_id": str(uuid.uuid4())}
                resp = {"jsonrpc": "2.0", "id": req.get("id"), "result": result}
                if fault != "unsigned":
                    g._sign(resp, sid, WRONG_SECRET if fault == "wrong_signature" else g.hmac_secret)
                self._send(200, json.dumps(resp).encode(), "application/json", record,
                           fault_applied=fault if method == GATE_METHOD else None)

            def _send(self, status: int, body: bytes, ctype: str, record: dict, *, fault_applied) -> None:
                record.update({"method": (record.get("request") or {}).get("method"), "fault_applied": fault_applied,
                               "response_status": status, "response_content_type": ctype,
                               "response_raw_b64": base64.b64encode(body).decode()})
                with g.lock:
                    g.exchanges.append(record)
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *a, **kw):
                return

        return Handler
