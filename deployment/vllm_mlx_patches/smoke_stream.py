"""Multi-slot system-KV cache smoke test using the streaming path.

The streaming path is what Claude Code uses and what we patched for LRU
multi-slot. Uses ~25K-token system prompts so prefill cost is large enough
to overshadow decode and reveal cache HIT vs MISS speedups.

Schedule: A, A, B, A, B
Expected:
    A1 -> MISS (cold)     long
    A2 -> HIT             short (cache works at all)
    B1 -> MISS (cold)     long
    A3 -> HIT             short (multi-slot: would MISS with single slot)
    B2 -> HIT             short (multi-slot: would MISS with single slot)
"""

from __future__ import annotations

import json
import time
import urllib.request

URL = "http://studio1.lab:8003/v1/chat/completions"
API_KEY = "703ccba9163393f769228e0c3d1b809b6897fa9b4a50972d"
MODEL = "qwen3-coder-30b-a3b"

PARAGRAPH_A = (
    "You are an expert security analyst working on intrusion response. "
    "Your tone is concise, evidence-driven, and never speculative. "
    "Cite tickets, timestamps, and detection rule IDs whenever you make a claim. "
    "Reference QRadar offenses by AE_ prefix and Tanium signals by DE_ prefix. "
    "Always quote the exact field values you saw, never paraphrase telemetry. "
)
PARAGRAPH_B = (
    "You are a senior software engineer specializing in distributed systems. "
    "Explain trade-offs, surface failure modes, and prefer simple, boring solutions. "
    "Never invent APIs; if something is unknown, say so explicitly. "
    "Show worked examples with concrete code, not pseudocode hand-waving. "
    "Cite the specific commit hash or PR number that introduced any behavior. "
)

# ~1000 reps -> roughly 25K-30K tokens, comparable to Claude Code's
# real-world system+tools prompt.
SYS_A = (PARAGRAPH_A * 1000).strip()
SYS_B = (PARAGRAPH_B * 1000).strip()


def call_stream(system: str, user: str, max_tokens: int = 32) -> dict:
    """Issue a streaming completion and time TTFT separately from total."""
    body = json.dumps(
        {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.0,
            "stream": True,
        }
    ).encode()
    req = urllib.request.Request(
        URL,
        data=body,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    t0 = time.monotonic()
    ttft = None
    pieces: list[str] = []
    output_tokens = 0
    prompt_tokens = 0
    with urllib.request.urlopen(req, timeout=600) as resp:
        for raw in resp:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if payload == "[DONE]":
                break
            try:
                obj = json.loads(payload)
            except json.JSONDecodeError:
                continue
            usage = obj.get("usage") or {}
            if usage:
                prompt_tokens = usage.get("prompt_tokens", prompt_tokens)
                output_tokens = usage.get("completion_tokens", output_tokens)
            choices = obj.get("choices") or []
            if not choices:
                continue
            delta = choices[0].get("delta") or {}
            text = delta.get("content")
            if text:
                if ttft is None:
                    ttft = time.monotonic() - t0
                pieces.append(text)
                output_tokens += 1
    total = time.monotonic() - t0
    return {
        "ttft_s": round(ttft, 2) if ttft is not None else None,
        "total_s": round(total, 2),
        "prompt_tokens": prompt_tokens,
        "output_tokens": output_tokens,
        "completion": "".join(pieces)[:60],
    }


def main() -> None:
    schedule = [
        ("A1 cold", SYS_A, "What's your tone?"),
        ("A2 warm", SYS_A, "What prefix for QRadar?"),
        ("B1 cold", SYS_B, "What's your specialty?"),
        ("A3 warm", SYS_A, "Cite or speculate?"),
        ("B2 warm", SYS_B, "Invent APIs?"),
    ]
    print(
        f"{'label':>8}  {'ttft':>6}  {'total':>6}  "
        f"{'prompt':>6}  {'out':>4}  response"
    )
    for label, system, user in schedule:
        r = call_stream(system, user)
        ttft = f"{r['ttft_s']:.2f}s" if r["ttft_s"] is not None else "-"
        print(
            f"{label:>8}  {ttft:>6}  {r['total_s']:>5}s  "
            f"{r['prompt_tokens']:>6}  {r['output_tokens']:>4}  "
            f"{r['completion']!r}"
        )


if __name__ == "__main__":
    main()
