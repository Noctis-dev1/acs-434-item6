"""Stub model endpoint for the #434 item 6 runs: an Anthropic /v1/messages server with no model behind it.

Every main-loop request (one that offers the Write tool) gets the same scripted turn: one Write call to
a fixed probe file. Once a tool_result is in the history, the stub ends the turn with a short text reply.
Any other request (titles, summaries, token counts) gets a plain text reply. Every request is logged, so a
run records exactly what the client sent and what the stub answered.
"""
from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROBE_CONTENT = "acs-434-item6 probe: this file exists only if the Write tool ran\n"


def _has_tool(body: dict, name: str) -> bool:
    return any(isinstance(t, dict) and t.get("name") == name for t in body.get("tools") or [])


def _has_tool_result(body: dict) -> bool:
    for msg in body.get("messages") or []:
        content = msg.get("content")
        if isinstance(content, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return True
    return False


class StubModel:
    def __init__(self, probe_path: str, *, port: int = 0) -> None:
        self.probe_path = probe_path
        self.log: list[dict] = []
        self.lock = threading.Lock()
        self._server = ThreadingHTTPServer(("127.0.0.1", port), self._handler_cls())
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()

    # The scripted turn, as a list of content blocks plus a stop reason.
    def plan(self, body: dict) -> tuple[list[dict], str, str]:
        if _has_tool(body, "Write") and not _has_tool_result(body):
            block = {"type": "tool_use", "id": f"toolu_{uuid.uuid4().hex[:24]}", "name": "Write",
                     "input": {"file_path": self.probe_path, "content": PROBE_CONTENT}}
            return [block], "tool_use", "write_probe"
        if _has_tool(body, "Write"):
            return [{"type": "text", "text": "Done."}], "end_turn", "finish"
        return [{"type": "text", "text": "Probe run"}], "end_turn", "aux"

    def _handler_cls(self):
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    body = json.loads(raw.decode() or "{}")
                except ValueError:
                    body = {}
                path = self.path.split("?")[0]
                if path.endswith("/count_tokens"):
                    self._json({"input_tokens": 10})
                    stub._record(path, body, "count_tokens", None)
                    return
                if not path.endswith("/v1/messages"):
                    self._json({"type": "error", "error": {"type": "not_found_error", "message": path}}, 404)
                    stub._record(path, body, "unknown_path", None)
                    return
                blocks, stop_reason, kind = stub.plan(body)
                model = body.get("model", "stub")
                stub._record(path, body, kind, blocks)
                if body.get("stream"):
                    self._stream(model, blocks, stop_reason)
                else:
                    self._json({"id": f"msg_{uuid.uuid4().hex[:24]}", "type": "message", "role": "assistant",
                                "model": model, "content": blocks, "stop_reason": stop_reason,
                                "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 10}})

            def do_GET(self):  # noqa: N802
                self._json({"data": [], "has_more": False})

            def _json(self, obj: dict, status: int = 200) -> None:
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _stream(self, model: str, blocks: list[dict], stop_reason: str) -> None:
                events = [("message_start", {"type": "message_start", "message": {
                    "id": f"msg_{uuid.uuid4().hex[:24]}", "type": "message", "role": "assistant", "model": model,
                    "content": [], "stop_reason": None, "stop_sequence": None,
                    "usage": {"input_tokens": 10, "output_tokens": 1}}})]
                for i, block in enumerate(blocks):
                    if block["type"] == "tool_use":
                        start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
                        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                    else:
                        start = {"type": "text", "text": ""}
                        delta = {"type": "text_delta", "text": block["text"]}
                    events += [("content_block_start", {"type": "content_block_start", "index": i, "content_block": start}),
                               ("content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta}),
                               ("content_block_stop", {"type": "content_block_stop", "index": i})]
                events += [("message_delta", {"type": "message_delta",
                                              "delta": {"stop_reason": stop_reason, "stop_sequence": None},
                                              "usage": {"output_tokens": 10}}),
                           ("message_stop", {"type": "message_stop"})]
                payload = "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a, **kw):
                return

        return Handler

    def _record(self, path: str, body: dict, kind: str, blocks: list[dict] | None) -> None:
        tool_results = []
        for msg in body.get("messages") or []:
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    inner = b.get("content")
                    if isinstance(inner, list):
                        inner = "".join(x.get("text", "") for x in inner if isinstance(x, dict))
                    tool_results.append({"is_error": bool(b.get("is_error")), "content": str(inner)[:2000]})
        with self.lock:
            self.log.append({"path": path, "kind": kind, "model": body.get("model"), "stream": bool(body.get("stream")),
                             "tools": [t.get("name") for t in body.get("tools") or [] if isinstance(t, dict)],
                             "n_messages": len(body.get("messages") or []), "tool_results": tool_results,
                             "answered": blocks})
