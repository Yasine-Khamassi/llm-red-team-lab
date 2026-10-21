"""
Manual chat with the Northwind bot, for exploring behaviour by hand.

    python -m app.cli                 # vulnerable mode
    python -m app.cli --defended      # guardrails on

Type 'quit' to exit.
"""

from __future__ import annotations

import argparse

from app.chatbot import respond, OllamaError


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--defended", action="store_true", help="apply guardrails")
    args = ap.parse_args()
    mode = "defended" if args.defended else "vulnerable"
    print(f"NorthwindBot ({mode}). Type 'quit' to exit.")
    while True:
        try:
            msg = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if msg.lower() in {"quit", "exit"}:
            return 0
        if not msg:
            continue
        try:
            turn = respond(msg, defended=args.defended)
        except OllamaError as exc:
            print(f"[error] {exc}")
            return 2
        print(f"bot> {turn.reply}")
        if turn.input_flagged:
            print(f"      (input flagged: {turn.input_reason})")
        if turn.secret_redacted:
            print("      (output guardrail redacted a secret)")


if __name__ == "__main__":
    raise SystemExit(main())
