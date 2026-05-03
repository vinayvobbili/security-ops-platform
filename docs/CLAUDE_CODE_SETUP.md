# 🤖 Claude Code → A Self-Hosted Local LLM

> Run Anthropic's Claude Code CLI against a model you host yourself.
> No API key. No usage caps. No per-token billing. Just point and go. ⚡

---

## 📑 Contents

- [What is Claude Code?](#-what-is-claude-code)
- [What you're getting](#-what-youre-getting)
- [1. Install Node.js](#1️⃣--install-nodejs)
- [2. Install Claude Code](#2️⃣--install-claude-code)
- [3. Stand up an Anthropic-compatible endpoint](#3️⃣--stand-up-an-anthropic-compatible-endpoint)
- [4. Configure the four magic env vars](#4️⃣--configure-the-four-magic-env-vars)
- [5. Take it for a spin 🚗💨](#5️⃣--take-it-for-a-spin-)
- [6. Your first real task — a 2-minute tutorial](#6️⃣--your-first-real-task--a-2-minute-tutorial)
- [The permission model](#️--the-permission-model--what-it-asks-before-doing)
- [Keyboard shortcuts cheat-sheet](#️--keyboard-shortcuts-cheat-sheet)
- [Recipe gallery](#-recipe-gallery--what-people-actually-use-this-for)
- [The CLAUDE.md trick](#-the-claudemd-trick--make-it-know-your-project)
- [Prefer an IDE? VS Code extension](#-prefer-an-ide-use-the-vs-code-extension)
- [Switching back to Anthropic's API](#-switching-back-to-anthropics-api)
- [Caveats](#️--caveats--read-this-once)
- [FAQ](#-faq)
- [Where to get help](#-where-to-get-help)
- [Status line](#-status-line--whats-at-the-bottom)
- [What about Claude Cowork?](#-what-about-claude-cowork)
- [References](#-references)

---

## 🧠 What is Claude Code?

Claude Code is a terminal-based AI pair-programmer. You run `claude` inside a project directory, type what you want in plain English, and it reads files, writes code, runs commands, and shows you a diff before saving. Think *"a teammate who pair-programs with you in your repo"* — not *"a chatbot in a browser tab."*

This guide walks through pointing Claude Code at a self-hosted model instead of Anthropic's cloud — same CLI, same workflow, just your own hardware doing the thinking.

---

## 🎯 What you're getting

|  | Claude Code on Anthropic API | Claude Code on a local LLM |
|---|---|---|
| **Cost** | 💵 per token | 🆓 free (your hardware) |
| **Network** | 🌍 internet | 🏠 wherever your model lives |
| **Auth** | Anthropic key | whatever your gateway requires |
| **Backend** | Claude (Opus / Sonnet / Haiku) | whatever you self-host |
| **Quality** | 🟢🟢🟢🟢🟢 | 🟢🟢🟢⚪⚪ (depends on the model) |
| **Privacy** | sent to Anthropic | stays on your network |

> 💡 **TIP** — 5 minutes to first prompt once you have a local model running. Four steps: install Node.js → install Claude Code → stand up an Anthropic-compatible endpoint → set 4 env vars.

---

## 1️⃣  Install Node.js

You need Node 18+ (LTS recommended).

### 🪟 Windows

One-liner via winget (built into Windows 10/11):

```powershell
winget install OpenJS.NodeJS.LTS
```

Or download the LTS installer from <https://nodejs.org> and click through the wizard — defaults are fine.

### 🍎 macOS

```bash
brew install node          # if you have Homebrew
# or download the .pkg from https://nodejs.org
```

### 🐧 Linux (Ubuntu / Debian)

```bash
curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
sudo apt install -y nodejs
```

### Sanity check

```bash
node --version    # → v20.x.x or later  ✅
npm --version
```

---

## 2️⃣  Install Claude Code

Same one-liner everywhere:

```bash
npm install -g @anthropic-ai/claude-code
```

```bash
claude --version    # → claude-code v1.x.x  ✅
```

> 🚨 **`claude: command not found`?** Your global npm bin isn't on PATH.
> - **Windows**: run `npm config get prefix` → add the resulting path (e.g. `%AppData%\npm`) to your user PATH in System Settings.
> - **Mac/Linux**: add `$(npm config get prefix)/bin` to `PATH` in your shell rc file.

---

## 3️⃣  Stand up an Anthropic-compatible endpoint

Claude Code speaks the **Anthropic API** (`POST /v1/messages`). Most local LLM servers (mlx-lm, Ollama, vLLM, llama.cpp) speak the **OpenAI-compatible API** (`/v1/chat/completions`). You'll need a small shim in between unless your server natively serves both.

Three options, ranked easiest → most flexible:

### Option A — Use a server that natively speaks Anthropic API

Some local servers ship with first-class Anthropic-format support. Check your server's docs for a `/v1/messages` route. If it has one, skip ahead — point Claude Code straight at it.

### Option B — LiteLLM proxy (recommended for most setups)

[LiteLLM](https://github.com/BerriAI/litellm) is a tiny proxy that translates between Anthropic ↔ OpenAI ↔ many other formats. Two-line setup:

```bash
pip install litellm
litellm --model openai/<your-model> --api_base http://localhost:11434/v1 --port 4000
```

That gives you `http://localhost:4000` speaking Anthropic-format on top of your existing OpenAI-compat backend.

### Option C — Hand-rolled shim

If you want full control (custom routing, fallbacks, header rewriting), write your own. There's a worked example shim under [`deployment/`](../deployment/) in this repo that accepts Anthropic format on the way in, translates to OpenAI on the way out, and falls back to a secondary backend on errors.

---

## 4️⃣  Configure the four magic env vars

These point Claude Code at your local endpoint instead of Anthropic's servers.

| Variable | Value |
|---|---|
| `ANTHROPIC_BASE_URL` | URL of your Anthropic-format endpoint, e.g. `http://localhost:4000` |
| `ANTHROPIC_AUTH_TOKEN` | Whatever your gateway requires (any string if it doesn't authenticate) |
| `ANTHROPIC_MODEL` | Whatever your gateway advertises — often `default` or your model name |
| `ANTHROPIC_SMALL_FAST_MODEL` | Same — usually the same model unless you split slow/fast tiers |

> 📘 **NOTE** — Claude Code expects *something* in the model field. If your gateway doesn't care, set it to `default` or any string. Many local servers report `default` from `/v1/models`.

### 🍎🐧 macOS / Linux — make it permanent

```bash
cat >> ~/.zshrc <<'EOF'

# 🤖 Claude Code → local LLM
export ANTHROPIC_BASE_URL="http://localhost:4000"
export ANTHROPIC_AUTH_TOKEN="local-dev-token"
export ANTHROPIC_MODEL="default"
export ANTHROPIC_SMALL_FAST_MODEL="default"
EOF

source ~/.zshrc
```

Use `~/.bashrc` if you're on bash instead of zsh.

### 🪟 Windows — PowerShell, persistent (user-level)

```powershell
[Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL",         "http://localhost:4000", "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_AUTH_TOKEN",       "local-dev-token",       "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_MODEL",            "default",               "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_SMALL_FAST_MODEL", "default",               "User")
```

> 💡 **TIP** — Close and reopen PowerShell for the new env vars to take effect. For a one-off in the current shell, use `$env:ANTHROPIC_BASE_URL = "..."` instead.

---

## 5️⃣  Take it for a spin 🚗💨

```bash
claude
```

Inside the prompt, type `/status` — you should see your custom `ANTHROPIC_BASE_URL` listed. Then say hi:

```
> hi! introduce yourself in one sentence.
```

> 💡 **TIP** — A telltale sign you're on the local model: it usually won't claim to be Claude. That confirms the routing is correct. 🎉

---

## 6️⃣  Your first real task — a 2-minute tutorial

"Hello" is fine, but Claude Code is meant to write and edit code in real repos. Here's a quick walkthrough.

### ① Open a project (or start fresh)

```bash
mkdir hello-claude && cd hello-claude
claude
```

Or `cd` into an existing repo and run `claude` there — it'll see your code and can edit files in place.

### ② Ask it to build something concrete

At the prompt, paste:

```
> write a Python script `weather.py` that takes a city name on the
  command line and prints today's forecast. Use the open-meteo public
  API (no key needed). Add a --json flag for machine-readable output.
```

Claude Code will plan the file, write it, show you the diff, and ask before saving. Press `y` to accept, `e` to edit inline, or describe what you want changed and it'll redo the diff.

### ③ Iterate

```
> nice. now add a unit test that mocks the HTTP call,
  then run it.
```

It'll create the test file, run it, and show you the output. If the test fails, ask it to fix and re-run — it can read its own errors.

### ④ Useful slash commands

| Command | What it does |
|---|---|
| `/status` | Show current model, env vars, and working directory |
| `/clear` | Clear the conversation and start fresh |
| `/compact` | Compress earlier turns to free up context |
| `/init` | Generate a CLAUDE.md describing this repo's conventions |
| `/help` | Full command list |

### Tips for getting good results from a local model

- **Be specific.** *"Refactor this function for clarity, keep the public signature"* beats *"make it better."*
- **Smaller scopes win.** One file at a time. Long multi-file refactors are where smaller models struggle.
- **Show, don't tell.** Pasting a small example of the desired output usually gets you there faster than describing it.
- **Verify the diff.** Smaller models occasionally hallucinate an import or path — read the diff before accepting.
- **If it gets stuck in a loop, `/clear` and rephrase.** Don't keep nudging a confused conversation back on track.

> 💡 **TIP** — Run `claude` inside any repo — it'll respect the existing code style and any `CLAUDE.md` / `AGENTS.md` instructions it finds. That's the fastest way to get useful work out of it.

---

## 🛡️  The permission model — what it asks before doing

Claude Code never silently edits files or runs commands. Every side-effect goes through a prompt:

| Key | What it does |
|---|---|
| **`y`** (yes) | Accept the proposed change / run the command |
| **`n`** (no) | Reject it; the model will adjust based on your reasoning |
| **`e`** (edit) | Open the proposed diff and tweak it before saving |

It will ask before:

- Writing to or deleting a file
- Running shell commands (especially anything destructive)
- Installing packages or making network calls

> 💡 **TIP** — Press **Shift+Tab** inside Claude Code to cycle permission modes. *"Auto-accept edits"* stops the y/n prompt for file edits — great for fast iteration, but only flip it on once you trust what the model is doing in this session.

---

## ⌨️  Keyboard shortcuts cheat-sheet

These speed things up dramatically once you know them:

| Shortcut | What it does |
|---|---|
| `Esc` | Interrupt a running generation (model is rambling? stop it) |
| `Ctrl+C` | Quit Claude Code |
| `↑` / `↓` | Cycle through your previous prompts |
| `Tab` | Autocomplete file paths |
| `Shift+Tab` | Cycle permission modes (ask / auto-edit / plan-only) |
| `@filename` | Reference a file — model reads it as context |
| `!command` | Run a shell command in this session, pipe output to the model |
| `#text` | Save `text` as a memory line (sticks across turns in this session) |
| `/` | Browse slash commands (`/status`, `/clear`, `/help`, `/compact`, `/init` …) |

> 💡 **TIP** — `@` and `!` are the two biggest force-multipliers. `@src/auth.py explain this` is faster than copy-pasting the file. `!pytest -x` lets the model see the test failure and fix it.

---

## 📖 Recipe gallery — what people actually use this for

*"Write a script"* is the obvious one. Here are the high-value uses that newcomers usually don't think to try:

### ▸ Onboard yourself to an unfamiliar repo

```
> walk me through the architecture of this codebase. start with the
  entry points and how requests flow through the system.
```

### ▸ Diagnose a failing test

```
> !pytest tests/test_auth.py -x
> the failure above — figure out what's wrong and fix it.
```

### ▸ Write tests for code you didn't write

```
> @src/billing/invoice.py write pytest unit tests for the
  `calculate_total` function. cover the discount edge cases.
```

### ▸ Pre-PR self-review

```
> !git diff main...HEAD
> review this diff like a senior engineer. flag bugs, missing
  edge cases, and anything you'd push back on in a PR review.
```

### ▸ Refactor with intent

```
> @src/utils/parser.py refactor the parse_event function for
  clarity. keep the public signature identical and don't change
  behavior — i'll diff it.
```

### ▸ Explain something opaque

```
> @scripts/migrate_v3.sql explain what this migration does and
  what could go wrong if i run it on a 50M-row table.
```

### ▸ Add docstrings to legacy code

```
> @src/legacy/sync_engine.py add Google-style docstrings to every
  public method. don't change the code itself.
```

### ▸ Translate between languages

```
> @scripts/cleanup.sh port this bash script to Python with argparse.
  preserve the same flags and exit codes.
```

---

## 📝 The CLAUDE.md trick — make it know your project

Drop a `CLAUDE.md` file at the root of your repo and Claude Code reads it on every run. This is where you teach it your project's conventions so you don't have to repeat yourself in every prompt.

Generate a starter automatically:

```
> /init
```

Or hand-write something like:

```markdown
# Project: payments-service

## Conventions
- Python 3.11, formatted with `ruff format`
- All DB access goes through `db/repository.py` — never raw SQL
- Tests live next to the code: `foo.py` → `foo_test.py`
- Commit messages follow Conventional Commits (feat:, fix:, chore:)

## Don't touch
- `legacy/` — frozen, will be deleted next quarter
- Anything under `vendored/` — third-party copies, do not edit

## Useful commands
- `make test` — run the unit tests
- `make lint` — ruff + mypy
```

> 💡 **TIP** — The bigger the repo, the more `CLAUDE.md` pays off. A 20-line conventions file saves you from typing *"and use ruff format"* in every prompt for the rest of your life.

### …and what is AGENTS.md?

`AGENTS.md` is the cross-tool version of the same idea — an emerging open convention that's read by Claude Code, Cursor, Aider, OpenAI Codex CLI, Gemini CLI, and a growing list of others. Same file format and intent as `CLAUDE.md`, just a neutral name so one file serves every AI assistant the team uses. Most repos now ship `AGENTS.md` as the source of truth and keep a tiny `CLAUDE.md` that just says *"see AGENTS.md."*

A minimal example:

```markdown
# AGENTS.md

## About this repo
Internal data-pipeline service. Python 3.11, Postgres, deployed via
GitHub Actions to AWS ECS.

## Setup
- `make install` — set up the venv and install deps
- `make test` — run pytest with coverage
- `make lint` — ruff + mypy (must pass before merging)

## Conventions
- Type hints on every public function
- Imports sorted by `ruff` (already in `make lint`)
- Tests live next to the code: `foo.py` → `foo_test.py`
- Never commit secrets — use `.env.example` for new keys

## Architecture quick-take
- `pipeline/` — ingest, transform, load stages
- `api/` — FastAPI service, talks to pipeline output tables
- `infra/` — Terraform, do not edit by hand

## Don't touch
- `pipeline/legacy/` — being deleted in Q3
- Anything generated (look for `# AUTOGENERATED` headers)
```

> 📘 **NOTE** — If both `CLAUDE.md` and `AGENTS.md` exist, Claude Code reads both. Pick whichever fits your workflow — `AGENTS.md` if your team uses multiple AI tools, `CLAUDE.md` if it's just Claude Code.

---

## 🆚 Prefer an IDE? Use the VS Code extension

If living in a terminal isn't your thing, install the *"Claude Code"* extension from the VS Code marketplace. It opens Claude Code as a side panel inside VS Code, with the same env-var config you set up above — point it at your local endpoint and it works identically.

- Diffs render inline in the editor instead of in the terminal
- Selected code is auto-attached as context
- Same slash commands, same permission model

> 📘 **NOTE** — JetBrains IDEs have an equivalent plugin. Same env vars, same behavior — search the JetBrains Marketplace for *"Claude Code."*

---

## 🔄 Switching back to Anthropic's API

When you want Opus / Sonnet for the heavy lifting, just unset the four vars:

### 🍎🐧 macOS / Linux

Comment out or delete the export block from `~/.zshrc` / `~/.bashrc`, then source it again — or in the current shell:

```bash
unset ANTHROPIC_BASE_URL ANTHROPIC_AUTH_TOKEN ANTHROPIC_MODEL ANTHROPIC_SMALL_FAST_MODEL
```

### 🪟 Windows PowerShell

```powershell
[Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL",         $null, "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_AUTH_TOKEN",       $null, "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_MODEL",            $null, "User")
[Environment]::SetEnvironmentVariable("ANTHROPIC_SMALL_FAST_MODEL", $null, "User")
```

You'll then need to authenticate with your Anthropic API key, or run `claude login` to use your Claude.ai subscription.

---

## ⚠️  Caveats — read this once

A self-hosted local model is **not Claude**. What works well, what's degraded, what's not supported:

| Works ✅ | Degraded ⚠️ | Not supported ❌ |
|---|---|---|
| Code Q&A | Multi-file refactors | Prompt caching |
| Single-file edits | Long tool-use chains | Extended thinking |
| Short chats | Subtle reasoning over big contexts | Citations |
| Basic tool calls | Occasional malformed tool calls | Batch / Files API |

> 🚨 **WARNING** — Most local models have a smaller context window than Claude's 200K / 1M. Don't paste a 50K-line file and expect it to fit.

If something's genuinely broken (not just *"lower quality than Claude"*), the issue is most likely in your shim/proxy — those are the easiest layer to patch.

---

## ❓ FAQ

**Q: It told me it can't access the internet. Is something broken?**
A: No — that's expected if your local model runs offline by design. If you need to fetch a webpage or hit an external API, run the command yourself with `!curl ...` and pipe the output back in.

**Q: My output got cut off mid-sentence.**
A: You hit the context window. Run `/compact` to compress earlier turns, or `/clear` to start fresh. Most local models have a smaller window than Claude — keep conversations focused.

**Q: It hallucinated a function / import / file path.**
A: Known weakness of smaller models. Always read the diff before accepting (press `e` to edit). If it keeps inventing things, scope down — ask about one file at a time and use `@filename` to anchor it.

**Q: It refused to do something benign.**
A: Rephrase. Smaller models can be over-cautious. Adding context like *"this is my own project, the file is mine to edit"* usually unblocks it.

**Q: Tool calls are failing or producing malformed JSON.**
A: Common with smaller models that haven't been heavily trained on tool-use. Retry the prompt; if it persists, simplify the request (fewer tools, smaller scope) or check whether your model has a dedicated tool-use parser (e.g. mlx-lm's `--tool-call-parser` flag).

**Q: First response is slow, later ones are fast. Why?**
A: The model warms up after the first query. Subsequent prompts in the same session reuse the loaded weights and KV cache — that's normal, not a bug.

**Q: Can I use this for confidential data?**
A: Prompts and responses stay on your hardware — nothing is sent to Anthropic or any third party. Follow your normal data-handling policy, but you don't have the *"sending to a vendor"* worry.

**Q: Can I run two `claude` sessions at once?**
A: Yes. Open a second terminal in a different repo and go. They're independent — each has its own conversation context.

**Q: How do I see what env vars Claude Code is actually using?**
A: Inside the prompt, type `/status`. It shows the resolved `ANTHROPIC_BASE_URL`, model, working directory, and permission mode.

---

## 🆘 Where to get help

- **Inside Claude Code**: type `/help` to see the full command list.
- **Routing issues** (*"my requests aren't reaching the local endpoint"*): start with `/status` and confirm `ANTHROPIC_BASE_URL`, then `curl` the endpoint directly to check it's up.
- **Bugs in the model itself** (refused a reasonable task, kept hallucinating, malformed tool calls): try a different model or tweak your shim — those are the layers you control.
- **Questions about Claude Code itself** (CLI flags, slash commands, extensions): <https://docs.anthropic.com/en/docs/claude-code> — the public docs apply, just substitute your endpoint for the Anthropic API.
- **Issues with this guide**: open a GitHub issue on this repo.

---

## 📊 Status line — what's at the bottom

Claude Code shows a one-line status bar at the bottom of the terminal with at-a-glance info about your session. Example:

```
host (machine-label) you@example.com project-name $0.42 1h20m (main) [Opus 4.7 (1M context)] ctx:12% (120k/1M) in:1 out:53k t/s:68.9
⏵⏵ accept edits on (shift+tab to cycle)
```

Field by field:

- **`host (machine-label)`** — hostname / machine label
- **`you@example.com`** — current Claude account
- **`project-name`** — project (current working directory)
- **`$0.42`** — session cost so far
- **`1h20m`** — session duration
- **`(main)`** — current git branch
- **`[Opus 4.7 (1M context)]`** — model in use (will read your `ANTHROPIC_MODEL` value when pointed at a local LLM)
- **`ctx:12% (120k/1M)`** — context window usage
- **`in:1 out:53k`** — input / output token counts for the session
- **`t/s:68.9`** — output tokens per second
- **`⏵⏵ accept edits on`** — current permission mode (Shift+Tab cycles between ask / auto-accept / plan-only)

Customize via `/statusline` inside the prompt, or hand-edit the `statusLine` key in `~/.claude/settings.json`. You can pick which fields to show, reorder them, or plug in a custom shell command for fully bespoke output.

---

## 👥 What about Claude Cowork?

Claude Cowork is the autonomous task agent inside the Claude desktop app — it plans, calls tools, reads results, and handles multi-step work across your local files and apps. Common question: *can we point it at a local LLM the same way we point Claude Code?* Yes.

> 📘 **NOTE** — Cowork accepts any gateway that exposes `/v1/messages` and forwards the `anthropic-beta` and `anthropic-version` headers. If your shim already works for Claude Code, the wire protocol checks out.

### 🛠️  Configure Cowork — per-user, no enterprise tooling required

In the Claude desktop app:

1. **Help → Troubleshooting → Enable Developer Mode**
2. **Developer menu → Configure third-party inference**
3. Fill in:
   - **Connection type**: `Gateway`
   - **Base URL**: your local endpoint, e.g. `http://localhost:4000`
   - **API key**: your bearer token (or any string if your gateway doesn't auth)
   - **Auth scheme**: `bearer`
   - **Custom headers**: leave empty
4. **Save → restart the app**

> 💡 **TIP** — Cowork and Claude Code share `~/.claude/settings.json` on the same machine, so the auth token you pasted in Claude Code is reused — you only need to enter the gateway URL and auth scheme in the Cowork dialog.

### ⚠️  Caveats specific to Cowork

- **Quality drop is more painful here.** Cowork's pitch is autonomous multi-step orchestration — exactly the workload most local models struggle with (long tool-use chains, multi-file reasoning, big-context inference).
- **Tool calling is flakier than Claude Code.** Reported across the community on non-Claude backends. If a Cowork session goes off the rails, simplify the prompt or fall back to Claude Code.
- **Some Cowork-vs-Code config keys don't propagate identically yet.** If a setting *"feels off"* in Cowork after working fine in Code, re-check the Developer-mode dialog rather than assuming the gateway is broken.

> ⚠️ **IMPORTANT** — Cowork relies on agentic loops where the model plans → calls tools → reads results → re-plans across many turns. Local models handle single-file edits well; multi-step agentic work is their weakest spot. If Cowork feels rough, that's the model — not the routing.

### 🆚 Claude Code vs Claude Cowork on a local LLM

|  | Claude Code | Claude Cowork |
|---|---|---|
| **Setup** | 4 env vars in shell rc | Developer-mode dialog (per user) |
| **Backend protocol** | `/v1/messages` (Anthropic) | `/v1/messages` (Anthropic) |
| **Local-model fit** | 🟢🟢🟢🟢⚪ focused edits | 🟢🟢⚪⚪⚪ multi-step loops degrade |
| **Tool-call reliability** | 🟢🟢🟢🟢⚪ | 🟢🟢🟢⚪⚪ flakier |
| **Best for** | Code Q&A, single-file edits, tests | Hands-off multi-step tasks (when it works) |

> 💡 **TIP** — For most workflows, prefer Claude Code with a local endpoint over Cowork. Same backend either way, and Claude Code's tighter scope (one repo, focused edits) plays to local models' strengths. Reach for Cowork when you actually want hands-off multi-step orchestration.

---

## 📚 References

- [Use Claude Cowork with third-party platforms — Anthropic Help Center](https://support.claude.com/en/articles/14680729-use-claude-cowork-with-third-party-platforms)
- [Claude Code public documentation](https://docs.anthropic.com/en/docs/claude-code)
- [LiteLLM — Anthropic ↔ OpenAI proxy](https://github.com/BerriAI/litellm)
- [`deployment/`](../deployment/) — example hand-rolled shim in this repo

### 🐍 Test from Python

Once your env is set up, this scratch script confirms end-to-end reachability of your gateway from a Python client. Replace the URL and token with your own. `verify=False` skips TLS trust validation — fine for a quick smoke test, but for production scripts install the `truststore` package (`pip install truststore`) and call `truststore.inject_into_ssl()` so Python uses your system keychain.

```python
import requests

response = requests.post(
    "http://localhost:4000/v1/chat/completions",
    headers={"Authorization": "Bearer local-dev-token"},
    json={
        "messages": [
            {"role": "system",
             "content": "You're a fun loving pirate. Respond as JSON: {\"reply\": \"<your response>\"}"},
            {"role": "user", "content": "Hey! How are you doing?"},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.1,
    },
    verify=False,
)
print(response.json()["choices"][0]["message"]["content"])
```

---

*Happy hacking. 🎉*
