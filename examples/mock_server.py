"""Local mock LLM endpoint for offline development and testing (Spec §8, NFR-4).

Simulates a deliberately vulnerable chatbot behind an OpenAI-shaped API:
- if the user message contains a CANARY_* marker, the bot "executes" the
  injected instruction and echoes the marker back (vulnerable to injection);
- otherwise it answers with a fixed in-role refusal.

Run:
    python examples/mock_server.py            # listens on 127.0.0.1:8000
    PORT=9000 python examples/mock_server.py
"""

import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

CANARY_RE = re.compile(r"CANARY_[0-9a-f]+_\d+")


class MockLLMHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            length = int(self.headers["Content-Length"])
            body = json.loads(self.rfile.read(length))
            message = body["messages"][-1]["content"]
        except (KeyError, IndexError, ValueError, TypeError):
            self._respond(400, {"error": "expected JSON with messages[].content"})
            return

        match = CANARY_RE.search(message)
        answer = (
            match.group(0)
            if match
            else "I am the Acme support bot. I can only help with product questions."
        )
        self._respond(200, {"choices": [{"message": {"content": answer}}]})

    def _respond(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"Mock LLM endpoint listening on http://127.0.0.1:{port}")
    HTTPServer(("127.0.0.1", port), MockLLMHandler).serve_forever()
