# vllm-mlx local patches

Patches live here (not in the venv) so a `pip install --upgrade` of
`vllm-mlx` can't silently wipe them. `apply.sh` re-applies them on top of a
fresh install.

History: a prior round of patches (probe-divergence + incremental streaming
+ system-prompt KV cache) was carried here until it merged upstream as
`waybarrios/vllm-mlx#523` and was removed in IR commit `da014d10`. The
patch below is the next iteration on the same code path.

## multi_slot_lru_for_system_kv.patch

### Problem

PR #523 introduced a single-slot snapshot for the system-prompt KV cache
in `SimpleEngine`: `_system_kv_snapshot`, `_system_kv_hash`,
`_system_kv_token_count`. One system prefix is cached; a request with a
different system prefix replaces it.

In real Claude Code traffic the main agent and its sub-agents (Explore,
Plan, general-purpose) carry different toolsets, so each dispatches with a
different system prefix. Every sub-agent call evicts the main agent's
snapshot, and vice versa, so every turn pays the full cold-prefill cost.
On a 28K-token system+tools prompt that's a few minutes of TTFT — long
enough to hit the server's 300s request timeout, which kills the stream
before STORE runs and prevents the cache from ever populating.

### Fix

Replace the 3 single-slot instance vars with an `OrderedDict` LRU keyed by
the system-prefix hash. Each entry is `(snapshot_list, system_token_count)`.

* Capacity controlled by `VLLM_MLX_SYSTEM_KV_SLOTS` (default 4 — enough
  for main + 2-3 sub-agent variants).
* Gate stays read-only (`dict.get()` is atomic under the GIL and returns
  an immutable tuple, so a concurrent store can't desynchronize the
  captured snapshot from the hash that decided HIT).
* LRU `move_to_end` and eviction `popitem(last=False)` happen inside the
  serialized worker (`_run_blocking_serialized`), where the
  `_generation_lock` already prevents concurrent mutation.
* `EVICTED` log line emitted on capacity overflow.
* `mx.clear_cache()` after eviction to reclaim Metal heap.
* `get_stats()` returns per-slot breakdown instead of a single entry.

Both code paths get the same swap: the streaming `stream_chat` path
(what Claude Code uses) and the older non-stream text path.

### Validation (Qwen3-Coder-30B-A3B on studio1)

`smoke_stream.py` issues 5 streaming completions in the schedule
`A, A, B, A, B` with two distinct ~70K-token system prompts.
Measured time-to-first-token (TTFT) — the prefill-dominated metric:

| Step    | System | TTFT (cold/warm) | Status |
| ------- | ------ | ---------------- | ------ |
| A1 cold | A      | **144.29s**      | MISS → STORED 70008 tokens (6.9 GB) |
| A2 warm | A      | **0.85s**        | HIT 70008 |
| B1 cold | B      | **133.31s**      | MISS → STORED 67008 tokens (6.6 GB) |
| A3 warm | A      | **0.87s**        | HIT 70008 ← **only possible with multi-slot** |
| B2 warm | B      | **0.91s**        | HIT 67008 |

Speedup: **~170× on TTFT** (144s → 0.85s) on a warm system prefix.

The A3 step is the killer: with the previous single-slot snapshot, B1
would have evicted A's snapshot, and A3 would have been a 144s MISS again.
With the LRU at capacity 4, both A and B coexist and round-trip alternation
costs the same as repeated same-prompt traffic.

Two snapshots in memory at this scale = ~13.5 GB on a 96 GB Studio. Fits
comfortably; the engine continued to serve the embeddings collocated tenant
(`com.ir.vllm-mlx-embeds` on `:8004`) without issue.

### Applying

```bash
bash deployment/vllm_mlx_patches/apply.sh /Users/vvobbilichetty/vllm-venv
launchctl kickstart -k gui/$(id -u)/com.ir.vllm-mlx-coder
```

Backup at `simple.py.pre-multi-slot-lru` next to the patched file. Revert
by copying the backup back and restarting.

### Observability

The patch also adds `hits`/`misses`/`stores`/`evictions` counters plus
derived `hit_ratio` to `SimpleEngine`, exposed via the existing
`/v1/cache/stats` route:

```
$ curl -s -H "Authorization: Bearer $KEY" \
    http://studio1.lab:8003/v1/cache/stats | jq .engine_cache
{
  "system_kv_cache": {
    "capacity": 4,
    "in_use": 2,
    "counters": {"hits": 3, "misses": 2, "stores": 2, "evictions": 0, "hit_ratio": 0.6}
  }
}
```

This is the signal we were missing: the original PR #523 didn't expose
hit-ratio anywhere, so a 0%-effective cache was invisible until a user
complained about slow turns.

### Upstream contribution

Drafted in `PR_DRAFT.md` for a follow-up to `waybarrios/vllm-mlx#523`.
Bundle: multi-slot LRU + counters + the validation pattern that catches
the multi-prefix case the original #523 missed.
