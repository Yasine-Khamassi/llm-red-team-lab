"""
The Northwind support chatbot: a thin application wrapping a local Ollama model.

Two modes, selected per request:
- vulnerable: the raw model behind only its system-prompt instructions.
- defended: the same model with the guardrails in defenses/guardrail.py applied
  around it (input screening + output secret-redaction).

Run the server with `python -m app.server` from the 01-ai-red-teaming-lab
directory so the `app` and `defenses` packages resolve.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from app.config import MODEL, OLLAMA_URL, REQUEST_TIMEOUT, SYSTEM_PROMPT, TEMPERATURE
from defenses.guardrail import screen_input, screen_output, contains_system_prompt

REFUSAL = ("I can only help with Northwind Retail orders, returns, shipping and "
           "products. I can't help with that request.")


class OllamaError(RuntimeError):
    """Raised when the local Ollama server cannot be reached or errors."""


@dataclass
class Turn:
    reply: str
    defended: bool
    input_flagged: bool = False
    input_reason: str = "ok"
    secret_redacted: bool = False
    raw_model_output: str = ""
    meta: dict = field(default_factory=dict)


def _call_ollama(user_message: str) -> str:
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {"temperature": TEMPERATURE},
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat", data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:  # connection refused, DNS, timeout
        raise OllamaError(
            f"Could not reach Ollama at {OLLAMA_URL}. Is it installed and is the model "
            f"'{MODEL}' pulled? Original error: {exc}"
        ) from exc
    return (body.get("message") or {}).get("content", "")


def respond(user_message: str, defended: bool = False) -> Turn:
    """Runs one turn through the app in the chosen mode."""
    if defended:
        verdict = screen_input(user_message)
        if not verdict.allowed:
            # Input screening refuses likely injection/extraction outright, and
            # the attempt is still attributable in logs.
            return Turn(reply=REFUSAL, defended=True, input_flagged=True,
                        input_reason=verdict.reason, raw_model_output="")
        raw = _call_ollama(user_message)
        cleaned, leaked = screen_output(raw)
        if contains_system_prompt(cleaned):
            # System-prompt disclosure (LLM07): don't return a paraphrase of the
            # instructions; replace with a refusal and record the event.
            return Turn(reply=REFUSAL, defended=True, input_flagged=False,
                        input_reason=verdict.reason, secret_redacted=leaked,
                        raw_model_output=raw, meta={"prompt_blocked": True})
        return Turn(reply=cleaned, defended=True, input_flagged=False,
                    input_reason=verdict.reason, secret_redacted=leaked, raw_model_output=raw)

    raw = _call_ollama(user_message)
    return Turn(reply=raw, defended=False, raw_model_output=raw)
