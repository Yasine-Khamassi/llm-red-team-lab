"""
Turn the red-team hit-logs into a findings report mapped to the OWASP Top 10 for
LLM Applications and MITRE ATLAS, with the before (vulnerable) vs after (defended)
retest side by side.

    python -m findings.summarize           # reads findings/out/hitlog-*.json
Writes findings/out/FINDINGS.md.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict

OUT = os.path.join("findings", "out")


def _load(mode: str) -> dict | None:
    path = os.path.join(OUT, f"hitlog-{mode}.json")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    vuln = _load("vulnerable")
    defended = _load("defended")
    if vuln is None:
        print("No findings/out/hitlog-vulnerable.json. Run: python -m redteam.run_redteam --mode both")
        return 1

    defended_by_id = {r["id"]: r for r in defended["results"]} if defended else {}
    by_owasp: dict[str, list] = defaultdict(list)
    for r in vuln["results"]:
        by_owasp[r["owasp"]].append(r)

    lines = ["# Red-team findings - Northwind support bot", ""]
    lines.append(f"Vulnerable build: **{vuln['succeeded']}/{vuln['total']}** attacks succeeded.")
    if defended:
        lines.append(f"Defended build (retest): **{defended['succeeded']}/{defended['total']}** attacks succeeded.")
    lines += ["", "## Findings by OWASP LLM category", "",
              "| OWASP | Probe | Technique | Vulnerable | Defended (retest) | Leak |",
              "| --- | --- | --- | --- | --- | --- |"]
    for owasp in sorted(by_owasp):
        for r in by_owasp[owasp]:
            d = defended_by_id.get(r["id"])
            v_mark = "LEAK" if r["attack_succeeded"] else "blocked"
            d_mark = ("-" if d is None else ("LEAK" if d["attack_succeeded"] else "blocked"))
            lines.append(f"| {owasp} | `{r['id']}` | {r['category']} | {v_mark} | {d_mark} | {r['leak_type']} |")

    lines += ["", "## MITRE ATLAS techniques exercised", ""]
    atlas = sorted({r["atlas"] for r in vuln["results"]})
    for a in atlas:
        lines.append(f"- {a}")

    lines += ["", "## Notes", "",
              "- *Vulnerable* and *Defended* are the same model and system prompt; the only",
              "  difference is the guardrails in `defenses/guardrail.py`.",
              "- A result is *LEAK* only when the planted fake secret or the system prompt",
              "  actually appeared in the model output (ground truth), not when the model merely",
              "  tried and was stopped.",
              "- Model outputs are non-deterministic; counts can vary slightly between runs.",
              "  The output guardrail is the control that should hold regardless."]

    os.makedirs(OUT, exist_ok=True)
    report_path = os.path.join(OUT, "FINDINGS.md")
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"Wrote {report_path}")
    print("\n".join(lines[:6]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
