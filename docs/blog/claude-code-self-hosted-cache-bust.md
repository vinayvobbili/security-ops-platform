---
layout: doc
title: "The 81 bytes killing my self-hosted Claude Code"
date: 2026-05-07
---

# The 81 bytes killing my self-hosted Claude Code

*2026-05-07 — Vinay Vobbilichetty*

Anthropic's [Claude Code](https://docs.claude.com/en/docs/claude-code) is a great
agentic coding CLI, but it talks to Anthropic's cloud by default. Its system
prompt is also huge — tens of thousands of tokens of tools, examples, and
behavior rules. If you front it with a self-hosted model and don't reuse that
prefix turn-over-turn, you're paying a full 30K+ token prefill on every single
keystroke that triggers a turn.

This post is the story of getting it from "100s+ per turn, even on `Hello`" to
sub-10s on follow-ups, and the surprisingly small thing that was sabotaging
the cache the whole time.

> **Update (after publishing)**: searching the vllm-mlx tracker turned up
> [PR #277](https://github.com/waybarrios/vllm-mlx/pull/277) by `janhilgard`,
> merged 2026-04-11 — the same finding as mine, plus a one-line regex strip
> in `vllm_mlx/anthropic_adapter.py`. Their numbers (50s → 3.65s, 13.7x) are
> nearly identical to mine. So this isn't a novel discovery; it's a
> rediscovery. **What's still useful about my version**: PR #277's strip
> only fires on direct `/v1/messages` traffic. My setup goes Claude Code →
> [`claude-code-router`](https://github.com/musistudio/claude-code-router)
> (translates Anthropic Messages → OpenAI chat completions) → vllm-mlx's
> `/v1/chat/completions` endpoint. The upstream's adapter-level strip
> doesn't fire on that path, so I had to do the same strip one layer up in
> the shim. The rest of this post is the original walkthrough — the
> rediscovery story still has value if you're routing through a translator
> layer, and the SimpleEngine KV-cache patch is independently useful since
> SimpleEngine has no built-in prefix cache.

## Setup

Two Apple Silicon Mac Studios behind a small front-door:

- **`claude-code-router`** (open source, Anthropic-Messages → OpenAI-chat
  bridge) on port 8050.
- **A 90-line FastAPI shim** in front of it on 8051, which adds the things
  vanilla `claude` clients need that ccr doesn't ship: `/v1/models`
  discovery, friendly model id aliases (`glm-4.7-flash` →
  `provider,exact-model-id`), Anthropic-style error sanitization, and a
  buffer-to-stream path for parsers whose tool-call streaming is broken.
- **vllm-mlx** (the mlx-lm-backed fork of vLLM, OpenAI-compatible API)
  running two models — GLM-4.7-Flash for general work, Qwen2.5-Coder-32B for
  coding-helper traffic — each on its own port.

Single user, single model at a time, single physical box per model. No
batching, no parallelism. The simplest possible serving topology. And it was
slow enough to be unusable: every turn took a hundred-plus seconds, even on
trivial prompts.

## Step 1: confirm the bottleneck

A `Hello` prompt should generate maybe 5-10 output tokens. If a 5-token reply
still takes 100+ seconds on a Mac Studio, the model is not the problem —
**prefill is**. Claude Code's stock system prompt is roughly 30,000-40,000
tokens of tool definitions and behavior rules. On Apple Silicon, prefilling
that on every turn from cold is exactly the kind of "100s of seconds, then a
few hundred ms of generation" profile I was seeing.

So: enable prefix caching.

## Step 2: vllm-mlx prefix caching is a trap

vllm-mlx 0.2.9 ships with two engines:

- **`BatchedEngine`** — has a real prefix cache (block-table, paged KV,
  multi-slot trie). This is what you want.
- **`SimpleEngine`** — what runs by default. No prefix cache at all. Every
  request prefills from scratch.

To enable BatchedEngine you set `--continuous-batching`. Easy fix, right?

```
$ vllm-mlx serve … --continuous-batching
…
RuntimeError: There is no Stream(gpu, X) in current thread
```

This is an mlx-lm 0.31.3 bug. mlx-lm's GPU stream object is created on one
thread, but vllm-mlx's BatchedEngine workers run generation on a different
thread, and mlx refuses to use a stream from outside its creating thread.
Without re-architecting either project, this path is dead.

## Step 3: a SimpleEngine patch, hash-keyed

If I can't have BatchedEngine's nice cache, I can give SimpleEngine a poor
person's version: cache exactly one snapshot of the KV state right after the
system prompt has been prefilled, keyed by the hash of the system prefix
text. On the next request, if the hashes match, restore the snapshot and
only prefill the suffix (recent user/assistant turns).

The patch is about 170 lines. Sketch:

```python
# Detect system prefix via ChatML markers
for marker in ("<|im_start|>user\n", "<|im_start|>assistant\n"):
    idx = prompt.find(marker)
    if idx > 0:
        system_prefix_end = idx
        break

system_prefix_text = prompt[:system_prefix_end]
system_hash = hashlib.sha256(system_prefix_text.encode()).hexdigest()[:16]

if system_hash == cached_hash:
    # HIT — restore snapshot, prefill only suffix
    backbone_cache = [c.copy() for c in cached_state]
    suffix_tokens = full_tokens[system_token_count:]
else:
    # MISS — prefill system, snapshot, then continue with suffix
    backbone_cache = make_prompt_cache(model)
    _prefill(system_tokens, backbone_cache)
    cached_state = [c.state for c in backbone_cache]
    cached_hash = system_hash
    suffix_tokens = full_tokens[system_token_count:]
```

(Full patch and apply script are at
[`deployment/vllm_mlx_patches/`](https://github.com/vinayvobbili/security-ops-platform/tree/main/deployment/vllm_mlx_patches)
in this repo.)

I wrote a synthetic test: same 38K-token system prompt, two consecutive
requests, one with the cache and one without. **17x speedup on the second
request.** Lock that in, ship to the upstream model server, point Claude
Code at it.

Turn 1: 1m 48s. Cold start, miss.
Turn 2: **1m 47s**.

Wait, what?

## Step 4: the cache works, except when it doesn't

I went back and verified the synthetic test still showed 17x. It did. So the
patch is correct *in isolation*. Something about Claude Code's actual
traffic was busting the cache that wasn't busted by my test harness.

Time to look at the real payloads. The shim has an env-var-gated capture
mode that dumps every `/v1/messages` request body to disk. Enable it, run
two turns of Claude Code against it, diff:

```bash
$ diff turn-1.json turn-2.json
…
< "text": "x-anthropic-billing-header: cc_version=2.0.45; cc_entrypoint=cli; cch=4f2a1"
---
> "text": "x-anthropic-billing-header: cc_version=2.0.45; cc_entrypoint=cli; cch=8b3c9"
```

That's the only thing that changed. Eighty-one bytes. One five-character
hex value (`cch=...`) rotates per turn. Everything else in the system
prefix — the entire 38K tokens — is byte-identical between turns.

But because my cache key is `sha256(prefix_text)`, those 81 bytes change the
hash, and every turn is a miss.

`cch` appears to be Claude Code's per-turn conversation/billing token. It
makes total sense for Anthropic's cloud — they need to attribute usage
across turns. To a self-hosted upstream, it's just a rotating cache-buster
sitting in the middle of an otherwise stable system prompt.

## Step 5: the five-line fix

Strip it in the shim, before forwarding upstream:

```python
def _strip_billing_header(payload: dict) -> None:
    system = payload.get("system")
    if not isinstance(system, list):
        return
    payload["system"] = [
        b for b in system
        if not (
            isinstance(b, dict)
            and isinstance(b.get("text"), str)
            and b["text"].lstrip().lower().startswith("x-anthropic-billing-header")
        )
    ]
```

That's it. Restart the shim, run Claude Code again:

```
> Hello
✻ Sautéed for 1m 48s        # cold cache, prefill the whole prefix

> Give me Python code that computes a SHA-256
✻ Sautéed for 8s            # HIT — restore snapshot, prefill ~30 tokens

> What is 2 + 2?
✻ Sautéed for 7s            # HIT — same prefix hash
```

Same `54ebf1c946b20c63` system-prefix hash on turns 2 and 3 in the upstream
logs. The cache is doing what it should — the prefix was always stable
modulo the billing header.

## Why this is still worth posting

Most of the writing on self-hosting Claude Code stops at "use a router, set
the env vars, point it at your model." That's enough to make it work. It is
not enough to make it fast. The default user experience of Claude Code on a
self-hosted backend is *bad* — minutes per turn — because the system prompt
is enormous and the cache hooks aren't there by default.

There are three traps in a row:

1. **vllm-mlx SimpleEngine has no prefix cache.** The fast engine
   (`--continuous-batching`) crashes on current mlx-lm because of a
   thread/stream ownership bug
   ([mlx-lm#1256](https://github.com/ml-explore/mlx-lm/issues/1256) is the
   open issue tracking it; vllm-mlx's
   [PR #478](https://github.com/waybarrios/vllm-mlx/pull/478) is the
   in-flight downstream fix). So if you're stuck on SimpleEngine, you have
   to bring your own caching.
2. **A prefix-hash cache works on synthetic tests but fails against real
   Claude Code traffic** if the upstream sees a rotating header inside the
   system prompt — `cch=` in `x-anthropic-billing-header` rotates per turn.
3. **vllm-mlx already strips this**
   ([PR #277](https://github.com/waybarrios/vllm-mlx/pull/277)), but **only
   on its `/v1/messages` adapter path.** If your client routes through a
   translator (Claude Code → ccr → OpenAI chat completions), the strip
   doesn't fire and you'll see the same cache-miss-every-turn behavior even
   on a recent vllm-mlx install.

If you're fronting Claude Code with a self-hosted LLM and your "cache hit"
turns aren't fast, the very first thing to check is whether the system
block your upstream sees is byte-stable across consecutive turns. A 5-line
diff of two captured payloads is all it takes to find this — whether the
underlying fix lives in the upstream, in your translator, or one layer up
in a shim like mine.

## What to do if you hit this

If you're running Claude Code against a self-hosted model:

1. **Confirm the symptom.** Run a couple of turns and look at how long
   prefill is on each. If turn 2 is roughly the same as turn 1 on a stable
   conversation, you're missing the cache.
2. **Capture the payloads.** Put a transparent proxy or a logging shim
   in front of your upstream and write the request body to disk for two
   consecutive turns. Diff them. Anything that changes between them is
   either signal the model needs (recent user/assistant turns) or noise that
   should be stripped.
3. **Strip the rotating bits.** For Claude Code specifically, the
   `x-anthropic-billing-header` system block is safe to drop — your local
   model has no use for it. If you hit vllm-mlx's
   [`/v1/messages`](https://github.com/waybarrios/vllm-mlx/pull/277)
   directly, this is already stripped for you. If you go through a
   translator (ccr / litellm / similar) into the OpenAI chat completions
   endpoint, you'll need to strip it yourself. Other clients may have
   their own equivalents.
4. **Then enable a prefix cache that actually works.** On vllm-mlx
   SimpleEngine that means a patch like the one linked above; on other
   stacks, use whatever real prefix-cache implementation the engine ships.

## Repo

- [`deployment/claude_router_shim.py`](https://github.com/vinayvobbili/security-ops-platform/blob/main/deployment/claude_router_shim.py)
  — the FastAPI shim, including `_strip_billing_header` and the capture mode
- [`deployment/vllm_mlx_patches/`](https://github.com/vinayvobbili/security-ops-platform/tree/main/deployment/vllm_mlx_patches)
  — the SimpleEngine system-prompt KV cache patch + idempotent applier
- [User setup guide](../CLAUDE_CODE_USER_SETUP) and
  [admin guide](../CLAUDE_CODE_ADMIN_SETUP) — how the whole thing is wired
  together if you want to reproduce it

If this saved you time, or if you spot something off, the repo is on
[GitHub](https://github.com/vinayvobbili/security-ops-platform) — issues
and PRs welcome.
