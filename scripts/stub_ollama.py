#!/usr/bin/env python3
"""Stand-in model for the lab: speaks Ollama's native API, returns a fixed reply. No LLM.

Why: DefenseClaw inspects the *prompt* before it reaches the model, so prompt-side detection
does not depend on which model answers. With this stub the OpenClaw agent runs through the
real gateway and DefenseClaw guardrail at zero API cost. DefenseClaw's interceptor routes
`localhost:11434` (Ollama's port) through the guardrail like any hosted provider.

NOT measured with the stub: canary leaks and completion-direction findings (the reply is
fixed). Runs made with it must say so (run notes); `clawshield doctor` proves interception.

Endpoints (as used by OpenClaw's `api: "ollama"` provider): GET /api/version, /api/tags,
/api/ps; POST /api/show, /api/chat (NDJSON stream or single JSON). Loopback only, request
bodies capped, never logged (they are attack strings).

    python3 scripts/stub_ollama.py [--port 11434]
"""

import argparse
import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "clawshield-stub"
REPLY = "[clawshield-stub] Placeholder reply: no language model is attached to this lab agent."
CONTEXT = 131072
MAX_BODY = 8 * 1024 * 1024
STATS: Counter[str] = Counter()


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


DETAILS = {"format": "gguf", "family": "stub", "families": ["stub"], "parameter_size": "0B",
           "quantization_level": "none"}  # fmt: skip
TAG = {"name": f"{MODEL}:latest", "model": f"{MODEL}:latest", "modified_at": _now(), "size": 0,
       "digest": "0" * 64, "details": DETAILS}  # fmt: skip


class Handler(BaseHTTPRequestHandler):
    server_version = "clawshield-stub/1"

    def log_message(self, fmt: str, *args: object) -> None:  # no request lines, no bodies
        return

    def _json(self, obj: object, status: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, object] | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._json({"error": "request too large"}, 413)
            return None
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._json({"error": "invalid JSON"}, 400)
            return None
        return data if isinstance(data, dict) else {}

    def do_GET(self) -> None:
        STATS[f"GET {self.path}"] += 1
        if self.path == "/api/version":
            self._json({"version": "0.0.0-clawshield-stub"})
        elif self.path == "/api/tags":
            self._json({"models": [TAG]})
        elif self.path == "/api/ps":
            self._json({"models": []})
        elif self.path in ("/", "/api"):
            self._json({"status": "ok"})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        STATS[f"POST {self.path}"] += 1
        req = self._body()
        if req is None:
            return
        if self.path == "/api/show":
            self._json({
                "modelfile": "", "parameters": f"num_ctx {CONTEXT}", "template": "",
                "details": DETAILS, "capabilities": ["completion", "tools"],
                "model_info": {"general.architecture": "stub", "stub.context_length": CONTEXT},
            })  # fmt: skip
        elif self.path == "/api/chat":
            self._chat(req)
        else:
            self._json({"error": "not found"}, 404)

    def _chat(self, req: dict[str, object]) -> None:
        model = str(req.get("model") or MODEL)
        messages = req.get("messages") if isinstance(req.get("messages"), list) else []
        prompt_chars = sum(len(str(m.get("content", ""))) for m in messages if isinstance(m, dict))
        final = {
            "model": model, "created_at": _now(),
            "message": {"role": "assistant", "content": ""}, "done": True, "done_reason": "stop",
            "total_duration": 1_000_000, "load_duration": 0, "prompt_eval_count": prompt_chars // 4,
            "prompt_eval_duration": 1, "eval_count": len(REPLY) // 4, "eval_duration": 1,
        }  # fmt: skip
        if req.get("stream") is False:
            self._json({**final, "message": {"role": "assistant", "content": REPLY}})
            return
        chunk = {"model": model, "created_at": _now(),
                 "message": {"role": "assistant", "content": REPLY}, "done": False}  # fmt: skip
        body = (json.dumps(chunk) + "\n" + json.dumps(final) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=11434)
    args = ap.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"clawshield-stub on http://127.0.0.1:{args.port} (model {MODEL})", flush=True)
    last = time.monotonic()
    server.timeout = 1
    try:
        while True:
            server.handle_request()
            if time.monotonic() - last > 300:  # periodic counts only
                print(f"{_now()} requests: {dict(STATS)}", flush=True)
                last = time.monotonic()
    except KeyboardInterrupt:
        print(f"stopped; requests: {dict(STATS)}", file=sys.stderr)


if __name__ == "__main__":
    main()
