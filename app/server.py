"""
Minimal HTTP wrapper around the Northwind chatbot so red-team tools (Promptfoo's
HTTP provider, Garak's REST generator, PyRIT's HTTP target) can attack the real
application - system prompt, planted secret and, optionally, guardrails - rather
than the bare model.

Run from the 01-ai-red-teaming-lab directory:
    python -m app.server
Endpoints:
    GET  /health            -> {"ok": true, "model": "..."}
    POST /chat  {"message": "...", "defended": false}  -> {"reply": "...", ...}
    The defended flag may also be set with ?defended=1 on the URL.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from app.chatbot import respond, OllamaError
from app.config import MODEL

PORT = int(os.environ.get("AISEC_PORT", "8099"))


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if urlparse(self.path).path == "/health":
            self._send(200, {"ok": True, "model": MODEL})
        else:
            self._send(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/chat":
            self._send(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid_json"})
            return
        message = payload.get("message", "")
        defended = bool(payload.get("defended", False))
        q = parse_qs(parsed.query)
        if "defended" in q:
            defended = q["defended"][0] not in ("0", "false", "")
        try:
            turn = respond(message, defended=defended)
        except OllamaError as exc:
            self._send(502, {"error": "ollama_unavailable", "detail": str(exc)})
            return
        self._send(200, {
            "reply": turn.reply,
            "defended": turn.defended,
            "input_flagged": turn.input_flagged,
            "secret_redacted": turn.secret_redacted,
        })

    def log_message(self, *args) -> None:  # keep the console quiet during scans
        return


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Northwind target on http://127.0.0.1:{PORT}  (model={MODEL})")
    print("POST /chat {\"message\": \"...\", \"defended\": false}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
