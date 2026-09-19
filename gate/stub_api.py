#!/usr/bin/env python3
"""Local stand-in for the model API. Answers every Anthropic Messages or OpenAI Responses request with a
one-word reply and logs each request (path, headers that matter, body size) as one JSON line to LOG.

A request reaching this stub is the gate's proof that the agent got past start-up, i.e. past the point
where repository hooks and MCP servers are loaded. No real credentials are involved.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = os.environ.get("LOG", "/tmp/api.log")
TOOL_FILE = os.environ.get("TOOL_FILE", "/tmp/stub-tool.json")  # if present: answer with this tool call once


def sse(events):
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in events).encode()


ANTHROPIC = [
    ("message_start", {"type": "message_start", "message": {
        "id": "msg_stub", "type": "message", "role": "assistant", "model": "stub", "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}}),
    ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
    ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
    ("content_block_stop", {"type": "content_block_stop", "index": 0}),
    ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                       "usage": {"output_tokens": 1}}),
    ("message_stop", {"type": "message_stop"}),
]

RESPONSE = {"id": "resp_stub", "object": "response", "status": "completed", "model": "stub",
            "output": [{"type": "message", "id": "msg_stub", "role": "assistant", "status": "completed",
                        "content": [{"type": "output_text", "text": "ok", "annotations": []}]}],
            "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
def anthropic_tool_use(tool):
    return [
        ("message_start", ANTHROPIC[0][1]),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {
            "type": "tool_use", "id": "toolu_stub", "name": tool["name"], "input": {}}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {
            "type": "input_json_delta", "partial_json": json.dumps(tool["input"])}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                           "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]


def pending_tool(body):
    """The planted tool call, if this request offers that tool and has not seen its result yet."""
    if not os.path.exists(TOOL_FILE) or b"tool_result" in body:
        return None
    tool = json.load(open(TOOL_FILE))
    return tool if f'"name":"{tool["name"]}"'.encode() in body.replace(b" ", b"") else None


OPENAI = [
    ("response.created", {"type": "response.created", "response": {**RESPONSE, "status": "in_progress", "output": []}}),
    ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": RESPONSE["output"][0]}),
    ("response.completed", {"type": "response.completed", "response": RESPONSE}),
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _log(self, body):
        with open(LOG, "a") as f:
            f.write(json.dumps({"method": self.command, "path": self.path, "bytes": len(body),
                                "has_key": bool(self.headers.get("x-api-key") or self.headers.get("authorization")),
                                "body_head": body[:4000].decode("utf-8", "replace")}) + "\n")

    def _send(self, code, payload, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        self._log(body)
        if self.path.split("?")[0].endswith("/messages"):
            tool = pending_tool(body)
            return self._send(200, sse(anthropic_tool_use(tool) if tool else ANTHROPIC), "text/event-stream")
        if self.path.split("?")[0].endswith("/responses"):
            return self._send(200, sse(OPENAI), "text/event-stream")
        if self.path.split("?")[0].endswith("/count_tokens"):
            return self._send(200, b'{"input_tokens": 1}', "application/json")
        self._send(404, b"{}", "application/json")

    def do_GET(self):
        self._log(b"")
        if self.path.split("?")[0].endswith("/models"):
            return self._send(200, b'{"data": [], "object": "list"}', "application/json")
        self._send(404, b"{}", "application/json")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
