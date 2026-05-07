# 🤖 Claude Code → Our Internal LLM

> **status: live** · **backend: internal** · **corp network only** · **cost: $0**

Run Anthropic's Claude Code CLI against our self-hosted models. No API key. No usage caps. No per-token billing. Just point and go. ⚡

| 🔒 100% Local | 💰 $0 Cost | 🏢 Our Infra |
|---|---|---|
| Every prompt and response stays on hardware we own. | No API key, no per-token billing, no usage caps. | Runs on Macs we own, fronted by lab-vm1 on the corp network. |

## 📑 Table of contents
- [What is Claude Code?](#-what-is-claude-code)
- [The headline](#-the-headline)
- [Speed & latency — what to expect](#️-speed--latency--what-to-expect)
- [1️⃣ Install Node.js](#1️⃣-install-nodejs)
- [2️⃣ Install Claude Code](#2️⃣-install-claude-code)
- [3️⃣ Configure five env vars](#3️⃣-configure-five-env-vars)
- [4️⃣ Take it for a spin](#4️⃣-take-it-for-a-spin)
- [Switch models on the fly](#️-switch-models-on-the-fly)
- [5️⃣ Your first real task](#5️⃣-your-first-real-task--a-2-minute-tutorial)
- [Permission model](#️-the-permission-model)
- [Keyboard shortcuts](#️-keyboard-shortcuts-cheat-sheet)
- [Recipe gallery](#-recipe-gallery)
- [The CLAUDE.md trick](#-the-claudemd-trick--make-it-know-your-project)
- [VS Code extension](#-prefer-an-ide-use-the-vs-code-extension)
- [Switching back to real Claude](#-switching-back-to-real-claude)
- [Caveats](#️-caveats--read-this-once)
- [Network gotchas](#-network-gotchas)
- [FAQ](#-faq--things-people-ping-me-about)
- [Where to get help](#-where-to-get-help)
- [References](#-references)

---

## 🧠 What is Claude Code?
Claude Code is a terminal AI pair programmer. You run `claude` in a project directory, type what you want in plain English, and it reads files, writes code, runs commands, and shows you a diff before saving. Think "a teammate who pair-programs in your repo," not "a chatbot in a browser tab."

With this setup, all of that runs against our self-hosted models instead of Anthropic's cloud. Same CLI, same workflow — just our hardware doing the thinking.

## ✨ The headline
Three local models exposed through one endpoint.

| Model id | Best for | Notes |
|---|---|---|
| `glm-4.7-flash` | Default — coding, tool use, chat | Quickest first token. The Opus and Sonnet picker tiers both point here. |
| `qwen2.5-coder-32b` | Coding-heavy sessions with lots of tool calls | Code-tuned 32B; alternative if GLM-Flash misbehaves on your task. |
| `laguna` | Long-form prose, summaries | Runs via Ollama; slower first hit (cold load). Wired to Haiku tier. |

---

## ⏱️ Speed & latency — what to expect

> **❗ Read this before you judge.** Every turn re-prefills the entire conversation. There is **no prompt cache** locally today. Plan for **1–3 minutes per turn**, not the sub-second feel of anthropic.com. Your first "Hi" can take 2+ minutes — that's the floor, not a bug.

Measured on studio1 (Apple Silicon, GLM-4.7-Flash 8-bit) with Claude Code's stock system prompt + ~60 tools:

| Turn | Typical latency | Why |
|---|---|---|
| First "Hi" in a fresh session | ≈ 90–150 s | Prefill of system prompt + tool definitions (~9K tokens) at ~90 tok/s. |
| Tool-using turn (read a file, suggest an edit) | ≈ 90–180 s | Same prefill plus the file you just attached + the prior turns. |
| Long session (10+ turns, large files in context) | Grows turn-over-turn | Conversation keeps re-prefilling. Use `/compact` and `/clear` proactively. |

### 🤔 Why so much slower than anthropic.com?
- **Prompt caching** — Anthropic caches your system prompt and tools server-side, so a repeat turn skips prefill entirely (sub-second first token). Our stack doesn't have this yet (the underlying flag is broken in our current mlx-lm version).
- **Hardware** — a Mac Studio is not a datacenter GPU. Cloud Claude runs on accelerator clusters with orders-of-magnitude more memory bandwidth.
- **Model size** — GLM-4.7-Flash is ~30 GB on disk; Opus / Sonnet are far larger and run on far bigger machines. Smaller model partly compensates for the slower hardware, but only partly.

### ✅ Good fit for
- Learning Claude Code's workflow without burning Anthropic credits.
- Single-file edits, code review, explanations of opaque code.
- Pre-PR self-review on small diffs.
- Anything where data shouldn't leave the LAN.

### 🚫 Less good fit for
- Tight iterative loops on large files (each turn pays full prefill).
- Multi-file refactors that need long agentic chains.
- Anything where you'd notice a 60-second wait every turn.

For those, switch back to real Claude — see "Switching back to real Claude" below.

---

## 1️⃣ Install Node.js
You need Node 18+ (LTS recommended).

### 🪟 Windows

> **🏢 Corp-managed laptop? Try Software Center first.** Open Software Center (Start menu → "Software Center"), search for **Claude**, click **Install**. If it's there, you're done — no admin prompt, no PATH wrangling. **Skip ahead to Step 3 (env vars)**. The rollout is still in progress though, so most laptops don't have it yet — if Claude isn't listed for you, use the winget steps below to install Node, then continue to Step 2.

If Software Center doesn't list Claude — install Node manually. The flags below work **without admin rights** and **on corp Wi-Fi**:
```powershell
winget install OpenJS.NodeJS.LTS --source winget --scope user
```

> **📘 Why those two flags** — `--source winget` pins the Microsoft *winget* source instead of the default *msstore*, which fails with `0x8a15005e` (server certificate did not match) on corp Wi-Fi because SSL inspection breaks the Microsoft Store source. `--scope user` installs Node into your profile only and modifies your user PATH; no admin elevation needed. Close and reopen your terminal afterwards so the new PATH takes effect.

### 🍎 macOS
```bash
brew install node
```

### 🐧 Linux (Ubuntu / Debian)
```bash
sudo apt install -y nodejs npm
```

Sanity check:
```bash
node -v && npm -v
```

---

## 2️⃣ Install Claude Code

> **🏢 Installed via Software Center on Windows?** You're done — SC installs Claude Code alongside Node. Skip to Step 3 (env vars).

Otherwise (Software Center doesn't list Claude yet, or you're on Mac/Linux), same one-liner everywhere:
```bash
npm install -g @anthropic-ai/claude-code
```
Verify:
```bash
claude --version
```

---

## 3️⃣ Configure five env vars
These point Claude Code at our internal endpoint and pick which local model each tier resolves to. Get the API key from the team lead.

### 🍎🐧 macOS / Linux — make it permanent
Open `~/.zshrc` (or `~/.bashrc` on bash) in your editor — pick whichever you have:
```bash
subl ~/.zshrc      # Sublime Text
code ~/.zshrc      # VS Code
nano ~/.zshrc      # nano (no install needed)
```
Append these five lines and save:
```bash
export ANTHROPIC_BASE_URL=https://<your-llm-host>/local-llm
export ANTHROPIC_AUTH_TOKEN=<your-bearer-token>
export ANTHROPIC_DEFAULT_OPUS_MODEL=glm-4.7-flash
export ANTHROPIC_DEFAULT_SONNET_MODEL=glm-4.7-flash
export ANTHROPIC_DEFAULT_HAIKU_MODEL=laguna
```
Reload:
```bash
source ~/.zshrc
```

### 🪟 Windows — PowerShell, persistent (user-level)
```powershell
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_BASE_URL',            'https://<your-llm-host>/local-llm', 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_AUTH_TOKEN',           '<your-bearer-token>', 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_DEFAULT_OPUS_MODEL',   'glm-4.7-flash',          'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_DEFAULT_SONNET_MODEL', 'glm-4.7-flash',          'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_DEFAULT_HAIKU_MODEL',  'laguna',             'User')
```
Then close and reopen the terminal.

### 🩺 Verify — confirm the values are set

Open a **fresh** terminal (so it picks up the new vars), then run the line for your shell. All five values should print non-empty — if any are blank, the vars didn't persist and `claude` will fall back to api.anthropic.com.

🪟 **PowerShell**
```powershell
$env:ANTHROPIC_BASE_URL; $env:ANTHROPIC_AUTH_TOKEN.Substring(0,8) + "..."; $env:ANTHROPIC_DEFAULT_OPUS_MODEL; $env:ANTHROPIC_DEFAULT_SONNET_MODEL; $env:ANTHROPIC_DEFAULT_HAIKU_MODEL
```

🪟 **Windows CMD**
```cmd
echo %ANTHROPIC_BASE_URL% & echo %ANTHROPIC_AUTH_TOKEN:~0,8%... & echo %ANTHROPIC_DEFAULT_OPUS_MODEL% & echo %ANTHROPIC_DEFAULT_SONNET_MODEL% & echo %ANTHROPIC_DEFAULT_HAIKU_MODEL%
```

🍎🐧 **macOS / Linux**
```bash
echo "$ANTHROPIC_BASE_URL"; echo "${ANTHROPIC_AUTH_TOKEN:0:8}..."; echo "$ANTHROPIC_DEFAULT_OPUS_MODEL"; echo "$ANTHROPIC_DEFAULT_SONNET_MODEL"; echo "$ANTHROPIC_DEFAULT_HAIKU_MODEL"
```

The token is truncated to its first 8 characters so you can sanity-check it's set without echoing the full secret to your terminal scrollback.

---

## 4️⃣ Take it for a spin
```bash
cd ~/some/repo
claude
```
Inside the prompt, type `/status` — confirm `ANTHROPIC_BASE_URL` shows https://<your-llm-host>/local-llm. Then say hi:
```
> hi, what model are you?
```

---

## 🎛️ Switch models on the fly

The five env vars in step 3 set your defaults. To try a different model for one session without editing your shell config, override at launch.

### ① Env-var prefix (one session)
```bash
ANTHROPIC_MODEL=qwen2.5-coder-32b claude
```
`ANTHROPIC_MODEL` takes precedence over the per-tier vars. Banner will read `qwen2.5-coder-32b[1m]` instead of the default. Closes the override when the session ends.

### ② CLI flag (one session)
```bash
claude --model qwen2.5-coder-32b
```
Same effect as the env-var prefix; pick whichever feels natural.

### ③ `/model` picker (mid-session)
Inside Claude Code, `/model` switches between the Opus / Sonnet / Haiku tiers. Each tier resolves to whichever id you set in `ANTHROPIC_DEFAULT_{OPUS,SONNET,HAIKU}_MODEL`. Useful if you wired Sonnet to `qwen2.5-coder-32b` — `/model` then becomes a GLM ↔ Qwen toggle without restarting.

> **💡 When to reach for each model.** Default to `glm-4.7-flash`. If a coding turn comes back empty, drops a tool call, or the model talks about code instead of writing it, retry with `qwen2.5-coder-32b` — it's code-tuned and doesn't have a thinking-mode prefix that can swallow short answers.

---

## 5️⃣ Your first real task — a 2-minute tutorial

### ① Open a project (or start fresh)
`cd` into an existing repo and run `claude` there — it'll see your code and edit files in place.

### ② Ask it to build something concrete
At the prompt, paste:
```
> add a simple is_palindrome(s) helper in utils.py with a unit test. Strip non-alphanumerics, ignore case.
```
Claude Code will plan the file, write it, show you the diff, and ask before saving. Press `y` to accept, `e` to edit inline, or describe what you want changed.

### ③ Iterate
```
> run the test
```
It'll create the test file, run it, and show output. If a test fails, ask it to fix and re-run.

### ④ Useful slash commands

| Command | What it does |
|---|---|
| `/status` | Show the resolved env vars, model, and working directory. |
| `/clear` | Reset the conversation in this session. |
| `/compact` | Compress earlier turns to free up context. |
| `/help` | Full command reference. |

### 💡 Tips for getting good results
- Be specific. "Refactor this function for clarity, keep the public signature" beats "make it better."
- Smaller scopes win. One file at a time. Long multi-file refactors are where local models struggle.
- Show, don't tell. Pasting a small example of the desired output usually beats describing it.
- Verify the diff. The model occasionally hallucinates an import or path — read before accepting.
- If it gets stuck, `/clear` and rephrase. Don't keep nudging a confused conversation.

---

## 🛡️ The permission model
Claude Code never silently edits files or runs commands. Every side-effect goes through a prompt. It will ask before:
- Writing to or deleting a file
- Running shell commands (especially anything destructive)
- Installing packages or making network calls

> **💡 Shift+Tab** cycles between three modes: ask (default), auto-accept edits, plan-only. Current mode shows in the bottom-of-terminal status line.

---

## ⌨️ Keyboard shortcuts cheat-sheet

| Shortcut | What it does |
|---|---|
| `Esc` | Cancel the current generation. |
| `Shift+Tab` | Cycle permission modes (ask / auto-accept / plan). |
| `Ctrl+R` | Toggle thinking mode. |
| `Ctrl+C` | Quit Claude Code. |
| `@filename` | Anchor a specific file as context. |
| `!cmd` | Drop into a shell, run cmd, pipe output back. |

---

## 📖 Recipe gallery
"Write a script" is the obvious one. Higher-value patterns most newcomers don't think to try:
- **Onboard yourself to an unfamiliar repo** — ask for a tour of `src/`, then have it explain the data model.
- **Diagnose a failing test** — paste the failure, ask for a hypothesis and a minimal repro.
- **Write tests for code you didn't write** — "add 5 unit tests covering edge cases of `parse_xyz`."
- **Pre-PR self-review** — "review the diff against main and flag anything that'd embarrass me."
- **Refactor with intent** — "extract the validation logic into a pure function, keep behavior identical."
- **Explain something opaque** — paste a regex, a SQL plan, a stack trace — ask for plain English.
- **Add docstrings to legacy code** — "add Google-style docstrings to all public methods in this file."
- **Translate between languages** — "port this Python function to Go, idiomatic."

---

## 📝 The CLAUDE.md trick — make it know your project
Drop a `CLAUDE.md` at the root of your repo and Claude Code reads it on every run. Teach it your conventions once instead of repeating yourself in every prompt.

Generate a starter automatically:
```
claude /init
```

`AGENTS.md` is the cross-tool version of the same idea — read by Claude Code, Cursor, Aider, Codex CLI, Gemini CLI. Same format, neutral name. Either works; teams that mix tools usually use AGENTS.md.

---

## 🆚 Prefer an IDE? Use the VS Code extension
Install the "Claude Code" extension from the VS Code marketplace. Same env-var config, same slash commands, same permission model — just rendered as a side panel in VS Code.
- Diffs render inline in the editor
- Selected code is auto-attached as context
- Same env vars work — no extra config

---

## 🔄 Switching back to real Claude
When you want real Opus / Sonnet for the heavy lifting, unset the five env vars:

### 🍎🐧 macOS / Linux
```bash
unset ANTHROPIC_BASE_URL ANTHROPIC_AUTH_TOKEN       ANTHROPIC_DEFAULT_OPUS_MODEL ANTHROPIC_DEFAULT_SONNET_MODEL ANTHROPIC_DEFAULT_HAIKU_MODEL
```

### 🪟 Windows PowerShell
```powershell
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_BASE_URL',            $null, 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_AUTH_TOKEN',             $null, 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_DEFAULT_OPUS_MODEL',   $null, 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_DEFAULT_SONNET_MODEL', $null, 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_DEFAULT_HAIKU_MODEL',  $null, 'User')
```
Then `claude login` to authenticate.

---

## ⚠️ Caveats — read this once

> **❗ Not Claude.** These are smaller open-weight models running on Mac hardware. Expect a quality drop from Opus / Sonnet, especially on long multi-file refactors and complex tool chains. Use them for what they're good at; reach for real Claude when the task warrants it.

- Smaller context window than Claude. Use `/compact` often, `/clear` when conversations drift.
- Tool-call reliability varies by model. If it loops or emits malformed JSON, simplify the prompt.
- Every turn re-prefills the conversation (no local prompt cache today) — see the Speed & latency section above.
- If something's genuinely broken (not just "lower quality than Claude"), file it.

---

## 🌐 Network gotchas
- Reachable from corp WiFi/wired LAN, or from home over the corp VPN.
- Not reachable from the corporate proxy-only or fully off-VPN networks.
- If `claude` hangs at startup, check that you can reach the gateway.

### 🩺 Quick reachability check
```bash
curl -H "Authorization: Bearer $ANTHROPIC_AUTH_TOKEN" $ANTHROPIC_BASE_URL/v1/models
```
Expected: a JSON list with `glm-4.7-flash` and `laguna`.

---

## ❓ FAQ — things people ping me about

**Q: 🪟 What's the easiest way to install on a corp-managed Windows laptop?**
A: Try **Software Center** first — search for **Claude**; if it's listed, click **Install** and you're done (no admin prompt, no PATH fiddling, jump to Step 3). The SC rollout is still in progress though, so most laptops don't have it yet — if Claude isn't there for you, fall back to the winget + npm steps in Step 1 and Step 2.

**Q: 🪟 winget install fails with "server certificate did not match" (`0x8a15005e`).**
A: If Claude is in your Software Center, that path skips winget entirely (search "Claude" → Install). Otherwise: corp SSL inspection breaks the Microsoft Store source. Pin winget explicitly: `winget install OpenJS.NodeJS.LTS --source winget`. The error message lists `winget` as a working source — that's the one to use.

**Q: 🪟 I don't have admin rights on my Windows laptop — can I still install?**
A: Yes. Easiest path is Software Center if Claude is listed for you (no admin needed). If it isn't, use winget with `--scope user`: `winget install OpenJS.NodeJS.LTS --source winget --scope user`. Node installs into your profile and only your user PATH is modified. Last-resort fallback is the portable zip from https://nodejs.org/dist/: extract to `%USERPROFILE%
odejs`, then add that folder to your **user** PATH (System Properties → Environment Variables → User variables → Path → New).

**Q: It told me it can't access the internet. Is something broken?**
A: No — that's expected. The local models run fully offline by design. To fetch a webpage, run `!curl ...` and pipe the output back in.

**Q: My output got cut off mid-sentence.**
A: You hit the context window. `/compact` to compress earlier turns, or `/clear` to start fresh.

**Q: It hallucinated a function / import / file path.**
A: Known weakness of smaller models. Always read the diff before accepting. If it keeps inventing things, scope down — ask about one file at a time and use `@filename` to anchor it.

**Q: It refused to do something benign.**
A: Rephrase. Adding context like "this is my own project, the file is mine to edit" usually unblocks it.

**Q: Tool calls are failing or producing malformed JSON.**
A: Simplify the request — break it into smaller steps.

**Q: Every turn feels slow. Why isn't the second one faster?**
A: Anthropic's cloud caches your system prompt + tools server-side, so repeat turns skip prefill. We don't have that locally yet — every turn re-prefills the conversation. The first turn pays for ~9K tokens of system prompt + tools; each subsequent turn pays for that plus everything since. Use `/compact` and `/clear` to keep context lean. See the Speed & latency section near the top of this doc for measured numbers.

**Q: Can I use this for confidential / customer data?**
A: Prompts and responses stay on our hardware — nothing is sent to Anthropic or any third party. Follow normal data-handling policy.

**Q: Can I run two `claude` sessions at once?**
A: Yes. Open a second terminal in a different repo. Independent contexts.

**Q: How do I see what env vars Claude Code is using?**
A: Type `/status` inside the prompt — shows resolved BASE_URL, model, permission mode, working directory.

---

## 🆘 Where to get help
- Inside Claude Code: `/help` for the full command list.
- Setup or routing issues: ping the team lead.
- Bugs in the model itself: file with the team lead so we can patch the bridge or tweak the config.
- Questions about Claude Code: https://docs.anthropic.com/en/docs/claude-code — public docs apply, just substitute our endpoint.

---

## 📚 References
- Claude Code official docs: https://docs.anthropic.com/en/docs/claude-code
- VS Code extension: search "Claude Code" in the marketplace
- Internal admin guide: `docs/CLAUDE_CODE_ADMIN_SETUP.md`
