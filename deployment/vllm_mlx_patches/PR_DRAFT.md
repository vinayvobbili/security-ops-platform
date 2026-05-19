# Upstream PR draft — multi-slot LRU for system-KV cache + counters

Follow-up to `waybarrios/vllm-mlx#523`. cc @Thump604 — touches the `SimpleEngine` stream/cache paths you own; would value your read.

**Title:** `feat: multi-slot LRU for system-KV cache + hit-ratio counters (follow-up to #523)`

---

## Problem

#523 introduced a single-slot system-prompt KV snapshot. Works on the validation pattern it shipped with (2 turns, same system prefix: 100s → 7s). Regresses to zero benefit the moment a client uses more than one system prefix in a session.

The case we hit: Claude Code's main-agent + sub-agent dispatch pattern interleaves two distinct system prefixes within one session:

- Main agent: ~28K tokens (system prompt + full toolset)
- Sub-agents (Explore / Plan / general-purpose): ~6–7K tokens

Every sub-agent dispatch evicts the main snapshot; every return to main re-prefills 28K cold. On Qwen3-Coder-30B-A3B that's ~140s TTFT per turn, which trips the server's 300s request timeout before the end-of-stream STORE runs, so the snapshot never lands. Cache stays empty across the entire session.

## Fix

### 1. Multi-slot LRU snapshot

Replace the 3 single-slot instance vars (`_system_kv_snapshot`, `_system_kv_hash`, `_system_kv_token_count`) with an `OrderedDict[str, tuple[list, int]]` LRU keyed by system-prefix hash.

- Capacity via `VLLM_MLX_SYSTEM_KV_SLOTS` env var, default **4** (covers main + 2–3 sub-agent variants with headroom). `=1` restores #523 behavior exactly.
- LRU `move_to_end()` / `popitem(last=False)` happen inside the serialized worker (`_run_blocking_serialized`), so the existing `_generation_lock` already prevents concurrent mutation.
- Gate read uses `dict.get()` returning an immutable `(snapshot, count)` tuple under the GIL — a concurrent store can't desync the snapshot from the hash that decided HIT.
- `EVICTED` log line on overflow; `mx.clear_cache()` after eviction to reclaim Metal heap.
- Applied to both `stream_chat` (the path Claude Code uses) and the older non-stream text path.

### 2. Counters + `/v1/cache/stats` exposure

Add `hits` / `misses` / `stores` / `evictions` counters to `SimpleEngine`, incremented only from inside the serialized worker (single writer, no locks). Exposed via a new `get_cache_stats()` method; the existing `/v1/cache/stats` route already picks it up via `hasattr(_engine, "get_cache_stats")`.

```json
{
  "engine_cache": {
    "system_kv_cache": {
      "capacity": 4,
      "in_use": 2,
      "counters": {
        "hits": 3, "misses": 2, "stores": 2, "evictions": 0,
        "hit_ratio": 0.6
      }
    }
  }
}
```

Rationale for bundling: #523's gap wasn't only the snapshot shape — it was that the cache could be 0% effective in production with no signal beyond log greps. Counters add ~10 LOC and let the next regression surface by metric, not by user complaint.

## Validation

`smoke_stream.py` (committed) runs `A, A, B, A, B` with two distinct ~70K-token system prompts on Qwen3-Coder-30B-A3B-Instruct-8bit:

| Step    | System | TTFT      | Cache event |
| ------- | ------ | --------- | ----------- |
| A1 cold | A      | 144.27s   | MISS → STORED 70008 tokens (6.9 GB) |
| A2 warm | A      | **0.85s** | HIT 70008 |
| B1 cold | B      | 133.33s   | MISS → STORED 67008 tokens (6.6 GB) |
| A3 warm | A      | **0.86s** | HIT 70008 ← only possible with multi-slot |
| B2 warm | B      | **0.81s** | HIT 67008 |

**~170× TTFT speedup on warm prefixes.** Under single-slot, B1 would evict A and A3 would be another 144s cold MISS. With the LRU at capacity 4, both prefixes coexist; round-trip alternation costs the same as repeated same-prefix traffic.

Post-run `/v1/cache/stats`:

```json
{"capacity": 4, "in_use": 2,
 "counters": {"hits": 3, "misses": 2, "stores": 2, "evictions": 0, "hit_ratio": 0.6}}
```

Memory: 2 snapshots × ~6.7 GB ≈ 13.5 GB on Metal heap. Collocated embeddings engine on the same Mac continued serving without issue.

## What this does **not** change

- System-prefix detection logic from #523 — untouched.
- Startup probe that disables snapshotting for sliding-window models (RotatingKVCache aliasing) — untouched.
- Decode-path codepath — identical.
- Single-slot behavior is recoverable: `VLLM_MLX_SYSTEM_KV_SLOTS=1`.

## Files touched

`vllm_mlx/engine/simple.py` only. ~270 lines of diff including counters; the cache-shape change itself is ~50 lines.

## Open questions

- Default capacity of **4** — defensible for Claude Code's main + 3 sub-agent variants. Env var keeps it tunable. Push higher?
- Should `clear_runtime_caches` (DELETE `/v1/cache`) also clear the system-KV LRU? Leaning yes for consistent "reset everything" semantics — happy to add if you want it in this PR.
- `hit_ratio` recomputed on every `/v1/cache/stats` read. Cheap today; could cache + invalidate on counter mutation if anyone scrapes high-frequency. Not worth complexity yet.
