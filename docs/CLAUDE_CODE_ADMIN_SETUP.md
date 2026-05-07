# 🛠️ Claude Code Local Stack — Admin Guide

> **scope: lab-vm1 + Mac fleet** · **consumers: any Claude Code client on corp net** · **status: production**

Operating manual for the router that lets Claude Code clients talk to our self-hosted vllm-mlx and Ollama backends.

| 🧠 2 backends | 🚪 1 endpoint | ⚙️ 2 services |
|---|---|---|
| studio1 GLM-Flash (vllm-mlx), studio1 Laguna (Ollama). | `lab-vm1:8051` — single URL, bearer-auth gated. | `ir-claude-router` (8050) + `ir-claude-router-shim` (8051). |

## 📑 Table of contents
- [Architecture](#-architecture)
- [Components & ports](#-components--ports)
- [Service operations](#️-service-operations)
- [Configuration files](#-configuration-files)
- [Adding a new model](#-adding-a-new-model)
- [Mac backends](#️-mac-backends)
- [Security & secrets](#-security--secrets)
- [Troubleshooting](#-troubleshooting)
- [Backup & recovery](#-backup--recovery)
- [References](#-references)

---

## 🧱 Architecture

Two services on lab-vm1, two Mac backends — both on studio1. The shim is the public face; ccr is the internal translator.

```
[claude client]
      │  ANTHROPIC_BASE_URL=http://lab-vm1:8051
      ▼
  lab-vm1:8051   ir-claude-router-shim   (FastAPI)
      │   • exposes GET /v1/models for SDK / curl discovery
      │   • rewrites friendly id → provider,model
      │   • bearer-auth gate
      ▼
  127.0.0.1:8050   ir-claude-router      (claude-code-router)
      │   • Anthropic /v1/messages → OpenAI /v1/chat/completions
      │   • routes by `provider,model` to one of two upstreams
      ▼
  ┌──────────────┬─────────────────────┐
  │ 8024         │ 8022                │
  │ studio1 GLM  │ studio1 Laguna      │
  │ vllm-mlx     │ Ollama              │
  └──────────────┴─────────────────────┘
  (each is a reverse SSH tunnel from studio1 into lab-vm1)
```

> **📌 Why two layers** — ccr handles the Anthropic↔OpenAI translation and multi-provider routing, but expects requests in `provider,model` form and doesn't expose `/v1/models` for discovery. The shim adds `/v1/models` (for SDK / curl / IDE-plugin enumeration), translates friendly model ids to ccr's `provider,model` form on incoming `/v1/messages`, and gates everything behind a bearer token. Note: Claude Code's `/model` picker is hardcoded to Opus / Sonnet / Haiku and does NOT read `/v1/models` — users wire each tier to one of our ids via `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL`. ~120 lines of FastAPI; no logic of its own beyond the rewrite.

---

## 📋 Components & ports

| Service | Port | Purpose | Source |
|---|---|---|---|
| `ir-claude-router` | 8050 | claude-code-router (npm). Anthropic↔OpenAI + provider routing. | `~/.claude-code-router/config.json` |
| `ir-claude-router-shim` | 8051 | FastAPI front door. `/v1/models` (discovery), id-rewrite, bearer auth. | `deployment/claude_router_shim.py` |

Backends (each lives behind a reverse SSH tunnel from its Mac):

| Tunnel port | Mac | Engine | Model |
|---|---|---|---|
| 8024 | studio1 | vllm-mlx | `mlx-community/GLM-4.7-Flash-8bit` |
| 8022 | studio1 | Ollama | `laguna-xs.2:q8_0` |

---

## ⚙️ Service operations

### 🩺 Status
```bash
systemctl --user status ir-claude-router ir-claude-router-shim
systemctl --user is-active ir-claude-router ir-claude-router-shim
```

### 🔄 Restart
```bash
# config.json edit → restart router
systemctl --user restart ir-claude-router

# claude_router_shim.py edit → restart shim
systemctl --user restart ir-claude-router-shim
```

### 📜 Logs

| Log | Path |
|---|---|
| Shim (Python uvicorn) | `data/transient/logs/claude_router_shim.log` |
| Router (ccr — systemd capture) | `data/transient/logs/claude_router.log` |
| Router (ccr — pino server) | `~/.claude-code-router/logs/ccr-*.log` |

---

## 🔧 Configuration files

### ① `~/.claude-code-router/config.json`
ccr config — providers, model lists, routing rules. Not under git (contains live URLs).

```json
{
  "HOST": "0.0.0.0",
  "PORT": 8050,
  "APIKEY": "$CCR_APIKEY",
  "Providers": [
    { "name": "glm",    "api_base_url": "http://127.0.0.1:8024/v1/chat/completions",
      "api_key": "sk-no-key",
      "models": ["glm-4.7-flash"] },
    { "name": "laguna", "api_base_url": "http://127.0.0.1:8022/v1/chat/completions",
      "api_key": "sk-no-key",
      "models": ["laguna-xs.2:q8_0"] }
  ],
  "Router": {
    "default":     "glm,glm-4.7-flash",
    "background":  "glm,glm-4.7-flash",
    "think":       "glm,glm-4.7-flash",
    "longContext": "glm,glm-4.7-flash"
  }
}
```

### ② `deployment/claude_router_shim.py`
Two dicts at the top decide what shows up in `/v1/models` and how aliases map to ccr providers. Edit, save, restart `ir-claude-router-shim`.

```python
MODEL_MAP = {
    "glm-4.7-flash":  "glm,glm-4.7-flash",
    "laguna":         "laguna,laguna-xs.2:q8_0",
}
DISPLAY_NAMES = {
    "glm-4.7-flash": "GLM 4.7 Flash",
    "laguna":        "Laguna xs.2",
}
```

### ③ `data/transient/.env` → `CCR_APIKEY`
Single bearer token validated by both the shim (own check) and ccr (forwarded). Clients send the same value as `Authorization: Bearer <CCR_APIKEY>` and as `ANTHROPIC_AUTH_TOKEN`.

> **⚠️ Keep the key out of git.** `.env` is gitignored. Distribute out-of-band (1Password, encrypted message). Rotate by regenerating, then restarting both services.

---

## ➕ Adding a new model
End-to-end walkthrough — example: `gemma3` on studio2.

### ① Stand up the model on the Mac
- Install vllm-mlx (or use the existing service plist as a template — see studio1 reference).
- Run with `--served-model-name gemma3` so the model id is human-readable; otherwise the full path is used.
- Bind to `127.0.0.1:<port>` on the Mac. Don't expose externally.

### ② Add a reverse SSH tunnel
On the Mac, edit `~/Library/LaunchAgents/com.ir.tunnel-to-labvm.plist` to add a new `-R <lab-vm-port>:127.0.0.1:<mac-port>` mapping. Pick a free lab-vm1 port (e.g. 8024). Reload with `launchctl kickstart -k gui/$(id -u)/com.ir.tunnel-to-labvm`.

Verify on lab-vm1:
```bash
curl -s http://127.0.0.1:8024/v1/models
```

### ③ Add provider to ccr config
Edit `~/.claude-code-router/config.json` — add a `Providers` entry:
```json
{ "name": "gemma",
  "api_base_url": "http://127.0.0.1:8024/v1/chat/completions",
  "api_key": "sk-no-key",
  "models": ["gemma3"] }
```

### ④ Add alias to the shim
Edit `deployment/claude_router_shim.py`:
```python
MODEL_MAP["claude-gemma3"]      = "gemma,gemma3"
DISPLAY_NAMES["claude-gemma3"]  = "Gemma 3"
```

### ⑤ Restart and verify
```bash
systemctl --user restart ir-claude-router ir-claude-router-shim

CCR_KEY=$(grep '^CCR_APIKEY=' data/transient/.env | cut -d= -f2)
curl -s -H "Authorization: Bearer $CCR_KEY" http://127.0.0.1:8051/v1/models | jq
```
Expected: the new `claude-gemma3` entry appears alongside the others.

---

## 🖥️ Mac backends

All three Claude Code backends now live on **studio1**, behind a single reverse-tunnel session to lab-vm1. (mac-m1 still runs GLM-4.7-Flash for Pokedex + Win.AI on its own tunnel, but is no longer in the Claude Code path as of 2026-05-06.)

### 🎙️ studio1 (GLM + Laguna, two stacks)
- vllm-mlx GLM: `mlx-community/GLM-4.7-Flash-8bit`, parser `glm47`, reasoning `deepseek_r1`, tunnel `lab-vm1:8024 → studio1:8002` (~30 GB on disk)
- Ollama: `laguna-xs.2:q8_0`, tunnel `lab-vm1:8022 → studio1:11434` (~40 GB cold, `KEEP_ALIVE=30s` so it unloads when idle)
- SSH backchannel: `ssh -p 2224 vvobbilichetty@127.0.0.1` from lab-vm1
- GLM reload: `launchctl bootout gui/$(id -u)/com.ir.vllm-mlx-glm && launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ir.vllm-mlx-glm.plist`
- Qwen3-32B vllm-mlx is downloaded (~33 GB) but the launchctl agent is **disabled** (2026-05-06) to avoid memory contention with GLM. Re-enable with `launchctl enable gui/$(id -u)/com.ir.vllm-mlx-qwen && launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ir.vllm-mlx-qwen.plist`.

> **⚠️ launchctl domain** — studio1's vllm-mlx services run in the `gui/$UID` domain, but the tunnel agent is in `user/$UID`. `launchctl print user/501` shows the vllm services as "enabled" but kickstart/bootout there fails with "Could not find service in domain." Use `gui/$(id -u)/...` for vllm; `user/$(id -u)/...` for the tunnel.

> **⚡ System-prompt KV cache patch** — vllm-mlx's `--continuous-batching` flag (which gates the engine-level prefix cache) crashes mlx-lm on first cache-hit decode with `RuntimeError: There is no Stream(gpu, X) in current thread`. We work around it with a local patch to `vllm_mlx/engine/simple.py` that adds single-slot system-prompt KV caching to the pure-LLM `stream_chat()` path. Result: ~17x speedup on cache hits (9.8s cold → 0.58s hit on Qwen2.5-Coder with a 2.5K-token system prompt). Patch + idempotent apply script: `deployment/vllm_mlx_patches/`. Re-run `apply.sh` after every `pip install --upgrade vllm-mlx` and bounce the launchctl agent.

---

## 🔐 Security & secrets
- Single bearer (`CCR_APIKEY`) validates both the shim and ccr.
- Shim binds `0.0.0.0` — accessible from any host on the corp network. No external exposure.
- ccr is bound `0.0.0.0` too but should only be hit via the shim. Future hardening: bind ccr to `127.0.0.1`.
- All traffic between lab-vm1 and the Macs is over reverse SSH tunnels (encrypted + key-auth).
- vllm-mlx and Ollama on the Macs bind `127.0.0.1` only — not reachable except through the tunnel.

### 🔁 Rotating the bearer token
```bash
# 1. regenerate
openssl rand -hex 32

# 2. update data/transient/.env
sed -i "s|^CCR_APIKEY=.*|CCR_APIKEY=<new-value>|" data/transient/.env

# 3. restart
systemctl --user restart ir-claude-router ir-claude-router-shim

# 4. distribute new value to users
```

---

## 🚨 Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| 401 on `/v1/models` | Wrong/missing bearer token | Check `ANTHROPIC_AUTH_TOKEN` matches `CCR_APIKEY` in `data/transient/.env`. |
| 404 on `/v1/models` | Client pointing at ccr (8050) instead of shim (8051) | Set `ANTHROPIC_BASE_URL=http://lab-vm1:8051`. |
| `/v1/messages` "fetch failed" | Upstream Mac unreachable | Check tunnel: `ss -tlnp \| grep 80<port>`. SSH the Mac, verify the engine is up. |
| Connection reset on GLM path | studio1 `vllm-mlx-glm` not running | ssh studio1, `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.ir.vllm-mlx-glm.plist`. |
| Picker doesn't show models | Stale gateway-models cache on client | Delete `~/.claude/cache/gateway-models.json` on client, restart `claude`. |
| Tool calls flaky | Model-specific (smaller models drop tool args) | Switch to `glm-4.7-flash` — most reliable for tool use. |
| Shim restart with no effect | Edited `config.json` but didn't restart ccr | Restart both for any provider change. |

---

## 💾 Backup & recovery
All four artifacts are tiny and rsync'd to lab-vm2 by the weekly backup cron:
- `~/.claude-code-router/config.json` — provider routing
- `deployment/claude_router_shim.py` — alias map (under git)
- `deployment/systemd/ir-claude-router*.service` — units (under git)
- `data/transient/.env` — `CCR_APIKEY` line

Recovery: restore those four files, `systemctl --user daemon-reload`, then start both services. No DB, no schema migrations.

---

## 📚 References
- User-facing setup guide: `docs/CLAUDE_CODE_USER_SETUP.docx`
- claude-code-router repo: https://github.com/musistudio/claude-code-router
- Memory: `~/.claude/projects/-home-vinay-IR/memory/project_claude_code_router.md`
- Memory: `~/.claude/projects/-home-vinay-IR/memory/project_studio1_qwen3_vllm.md`
- Generator script: `misc_scripts/build_claude_code_docs.py`
