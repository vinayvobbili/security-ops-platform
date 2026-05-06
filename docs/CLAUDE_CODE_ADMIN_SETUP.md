---
layout: default
title: Claude Code Setup — Admin Guide
---

# 🛠️ Claude Code Local Stack — Admin Guide

> **scope: lab-vm1 + Mac fleet** · **consumers: any Claude Code client on corp net** · **status: production**

Operating manual for the router that lets Claude Code clients talk to our self-hosted vllm-mlx and Ollama backends.

| 🧠 3 backends | 🚪 1 endpoint | ⚙️ 2 services |
|---|---|---|
| m1 GLM, studio1 Qwen (vllm-mlx), studio1 Laguna (Ollama). | `lab-vm1:8051` — single URL, bearer-auth gated. | `ir-claude-router` (8050) + `ir-claude-router-shim` (8051). |

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

Two services on lab-vm1, three Mac backends. The shim is the public face; ccr is the internal translator.

```
[claude client]
      │  ANTHROPIC_BASE_URL=http://lab-vm1:8051
      ▼
  lab-vm1:8051   ir-claude-router-shim   (FastAPI)
      │   • exposes GET /v1/models with claude-* aliases
      │   • rewrites alias → provider,model
      │   • bearer-auth gate
      ▼
  127.0.0.1:8050   ir-claude-router      (claude-code-router)
      │   • Anthropic /v1/messages → OpenAI /v1/chat/completions
      │   • routes by `provider,model` to one of three upstreams
      ▼
  ┌──────────────┬───────────────────┬─────────────────────┐
  │ 8015         │ 8023              │ 8022                │
  │ mac-m1 GLM   │ studio1 Qwen      │ studio1 Laguna      │
  │ vllm-mlx     │ vllm-mlx          │ Ollama              │
  └──────────────┴───────────────────┴─────────────────────┘
  (each is a reverse SSH tunnel from the Mac into lab-vm1)
```

> **📌 Why two layers** — ccr handles the Anthropic↔OpenAI translation and multi-provider routing, but doesn't expose `/v1/models`, so the `/model` picker stays empty. The shim adds `/v1/models` with claude-prefixed aliases, rewrites aliases on incoming `/v1/messages`, and forwards everything else through. ~120 lines of FastAPI; no logic of its own beyond the rewrite.

---

## 📋 Components & ports

| Service | Port | Purpose | Source |
|---|---|---|---|
| `ir-claude-router` | 8050 | claude-code-router (npm). Anthropic↔OpenAI + provider routing. | `~/.claude-code-router/config.json` |
| `ir-claude-router-shim` | 8051 | FastAPI front door. `/v1/models`, alias rewrite, bearer auth. | `deployment/claude_router_shim.py` |

Backends (each lives behind a reverse SSH tunnel from its Mac):

| Tunnel port | Mac | Engine | Model |
|---|---|---|---|
| 8015 | mac-m1 | vllm-mlx | `mlx-community/GLM-4.7-Flash-8bit` |
| 8023 | studio1 | vllm-mlx | `/Users/vvobbilichetty/models/Qwen3-32B-8bit` |
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
    { "name": "qwen",   "api_base_url": "http://127.0.0.1:8023/v1/chat/completions",
      "api_key": "sk-no-key",
      "models": ["/Users/vvobbilichetty/models/Qwen3-32B-8bit"] },
    { "name": "glm",    "api_base_url": "http://127.0.0.1:8015/v1/chat/completions",
      "api_key": "sk-no-key",
      "models": ["glm-4.7-flash"] },
    { "name": "laguna", "api_base_url": "http://127.0.0.1:8022/v1/chat/completions",
      "api_key": "sk-no-key",
      "models": ["laguna-xs.2:q8_0"] }
  ],
  "Router": {
    "default":     "qwen,/Users/vvobbilichetty/models/Qwen3-32B-8bit",
    "background":  "qwen,/Users/vvobbilichetty/models/Qwen3-32B-8bit",
    "think":       "qwen,/Users/vvobbilichetty/models/Qwen3-32B-8bit",
    "longContext": "qwen,/Users/vvobbilichetty/models/Qwen3-32B-8bit"
  }
}
```

### ② `deployment/claude_router_shim.py`
Two dicts at the top decide what shows up in `/v1/models` and how aliases map to ccr providers. Edit, save, restart `ir-claude-router-shim`.

```python
MODEL_MAP = {
    "claude-qwen3-32b":      "qwen,/Users/vvobbilichetty/models/Qwen3-32B-8bit",
    "claude-glm-4.7-flash":  "glm,glm-4.7-flash",
    "claude-laguna":         "laguna,laguna-xs.2:q8_0",
}
DISPLAY_NAMES = {
    "claude-qwen3-32b":     "Qwen3 32B",
    "claude-glm-4.7-flash": "GLM 4.7 Flash",
    "claude-laguna":        "Laguna xs.2",
}
```

### ③ `data/transient/.env` → `CCR_APIKEY`
Single bearer token validated by both the shim (own check) and ccr (forwarded). Clients send the same value as `Authorization: Bearer <CCR_APIKEY>` and as `ANTHROPIC_API_KEY`.

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

### 🍏 mac-m1 (GLM)
- Engine: vllm-mlx serving `mlx-community/GLM-4.7-Flash-8bit`
- Tool-call parser: `glm47`
- Tunnel: `lab-vm1:8015 → mac-m1:8015`
- SSH backchannel: `ssh -p 2223 vinay@127.0.0.1` from lab-vm1
- Reload: `launchctl kickstart -k gui/$(id -u)/com.ir.vllm-mlx-main`

### 🎙️ studio1 (Qwen + Laguna, two stacks)
- vllm-mlx: `Qwen3-32B-8bit`, parser `qwen`, tunnel `lab-vm1:8023`
- Ollama: `laguna-xs.2:q8_0`, tunnel `lab-vm1:8022`
- SSH backchannel: `ssh -p 2224 vvobbilichetty@127.0.0.1` from lab-vm1
- Qwen reload: `launchctl kickstart -k gui/$(id -u)/com.ir.vllm-mlx-qwen`

> **⚠️ launchctl domain** — studio1's vllm-mlx runs in the `gui/$UID` domain, not `user/$UID`. `launchctl print user/501` shows the service "enabled" but kickstart there returns "Could not find service in domain." Always use `gui/$(id -u)/...` for kickstart and bootout on studio1.

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
| 401 on `/v1/models` | Wrong/missing bearer token | Check `ANTHROPIC_API_KEY` matches `CCR_APIKEY` in `data/transient/.env`. |
| 404 on `/v1/models` | Client pointing at ccr (8050) instead of shim (8051) | Set `ANTHROPIC_BASE_URL=http://lab-vm1:8051`. |
| `/v1/messages` "fetch failed" | Upstream Mac unreachable | Check tunnel: `ss -tlnp \| grep 80<port>`. SSH the Mac, verify the engine is up. |
| Connection reset on Qwen path | studio1 vllm-mlx not running | ssh studio1, `launchctl kickstart -k gui/$(id -u)/com.ir.vllm-mlx-qwen`. |
| Picker doesn't show models | Stale gateway-models cache on client | Delete `~/.claude/cache/gateway-models.json` on client, restart `claude`. |
| Tool calls flaky | Model-specific (smaller models drop tool args) | Switch to `claude-qwen3-32b` — most reliable for tool use. |
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
