# 🤖 Claude Code → Our Internal LLM

> **status: live** · **backend: internal** · **corp network only** · **cost: $0**

Run Anthropic's Claude Code CLI against our self-hosted models. No API key. No usage caps. No per-token billing. Just point and go. ⚡

| 🔒 100% Local | 💰 $0 Cost | 🏢 Our Infra |
|---|---|---|
| Every prompt and response stays on hardware we own. | No API key, no per-token billing, no usage caps. | Runs on Macs we own, fronted by lab-vm1 on the corp network. |

## 📑 Table of contents
- [What is Claude Code?](#-what-is-claude-code)
- [The headline](#-the-headline)
- [1️⃣ Install Node.js](#1️⃣-install-nodejs)
- [2️⃣ Install Claude Code](#2️⃣-install-claude-code)
- [3️⃣ Configure two env vars](#3️⃣-configure-two-env-vars)
- [4️⃣ Take it for a spin](#4️⃣-take-it-for-a-spin)
- [5️⃣ Pick a model with /model](#5️⃣-pick-a-model-with-model)
- [6️⃣ Your first real task](#6️⃣-your-first-real-task--a-2-minute-tutorial)
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
Three local models exposed through one endpoint. Switch on the fly with `/model`.

| Model id | Best for | Notes |
|---|---|---|
| `claude-qwen3-32b` | Default — balanced reasoning + tool use | Largest of the three; uses a `<think>` block before answering. |
| `claude-glm-4.7-flash` | Fast iteration, code edits | Quickest first token. Great for inline edits and short tasks. |
| `claude-laguna` | Long-form prose, summaries | Runs via Ollama; slower first hit (cold load). |

---

## 1️⃣ Install Node.js
You need Node 18+ (LTS recommended).

### 🪟 Windows
```powershell
winget install OpenJS.NodeJS.LTS
```
Or download the LTS installer from https://nodejs.org and click through the wizard.

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
Same one-liner everywhere:
```bash
npm install -g @anthropic-ai/claude-code
```
Verify:
```bash
claude --version
```

---

## 3️⃣ Configure two env vars
These point Claude Code at our internal endpoint. Get the API key from the team lead.

### 🍎🐧 macOS / Linux — make it permanent
Append to `~/.zshrc` (use `~/.bashrc` on bash):
```bash
export ANTHROPIC_BASE_URL=http://lab-vm1:8051
export ANTHROPIC_API_KEY=<your-bearer-token>
```
Reload:
```bash
source ~/.zshrc
```

### 🪟 Windows — PowerShell, persistent (user-level)
```powershell
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_BASE_URL', 'http://lab-vm1:8051', 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_API_KEY', '<your-bearer-token>', 'User')
```
Then close and reopen the terminal.

> **📌 Only two vars** — earlier guides mentioned four. The lab-vm1 router now handles model selection through the `/model` picker, so the model env vars are no longer required.

---

## 4️⃣ Take it for a spin
```bash
cd ~/some/repo
claude
```
Inside the prompt, type `/status` — confirm `ANTHROPIC_BASE_URL` shows lab-vm1:8051. Then say hi:
```
> hi, what model are you?
```

---

## 5️⃣ Pick a model with /model
Inside Claude Code, type `/model`. The picker shows three entries:

| Pick | When to use it |
|---|---|
| `claude-qwen3-32b` | Default. Multi-step reasoning, tool calls, larger refactors. |
| `claude-glm-4.7-flash` | Snappy edits, quick questions, repetitive tasks. |
| `claude-laguna` | Long-form writing, doc generation, summaries. |

Claude Code remembers your pick for the session. To switch, run `/model` again.

---

## 6️⃣ Your first real task — a 2-minute tutorial

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
| `/model` | Pick a model from the local roster (qwen / glm / laguna). |
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
When you want Opus / Sonnet for the heavy lifting, unset the two env vars:

### 🍎🐧 macOS / Linux
```bash
unset ANTHROPIC_BASE_URL ANTHROPIC_API_KEY
```

### 🪟 Windows PowerShell
```powershell
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_BASE_URL', $null, 'User')
[System.Environment]::SetEnvironmentVariable('ANTHROPIC_API_KEY',  $null, 'User')
```
Then `claude login` to authenticate.

---

## ⚠️ Caveats — read this once

> **❗ Not Claude.** These are smaller open-weight models running on Mac hardware. Expect a quality drop from Opus / Sonnet, especially on long multi-file refactors and complex tool chains. Use them for what they're good at; reach for real Claude when the task warrants it.

- Smaller context window than Claude. Use `/compact` often, `/clear` when conversations drift.
- Tool-call reliability varies by model. If it loops or emits malformed JSON, simplify the prompt.
- First response in a session is slow (model warmup). Subsequent ones reuse the loaded weights.
- If something's genuinely broken (not just "lower quality than Claude"), file it.

---

## 🌐 Network gotchas
- Reachable from corp WiFi/wired LAN, or from home over the corp VPN.
- Not reachable from the corporate proxy-only or fully off-VPN networks.
- If `claude` hangs at startup, check that you can reach the gateway.

### 🩺 Quick reachability check
```bash
curl -H "Authorization: Bearer $ANTHROPIC_API_KEY" $ANTHROPIC_BASE_URL/v1/models
```
Expected: a JSON list with `claude-qwen3-32b`, `claude-glm-4.7-flash`, `claude-laguna`.

---

## ❓ FAQ — things people ping me about

**Q: It told me it can't access the internet. Is something broken?**
A: No — that's expected. The local models run fully offline by design. To fetch a webpage, run `!curl ...` and pipe the output back in.

**Q: My output got cut off mid-sentence.**
A: You hit the context window. `/compact` to compress earlier turns, or `/clear` to start fresh.

**Q: It hallucinated a function / import / file path.**
A: Known weakness of smaller models. Always read the diff before accepting. If it keeps inventing things, scope down — ask about one file at a time and use `@filename` to anchor it.

**Q: It refused to do something benign.**
A: Rephrase. Adding context like "this is my own project, the file is mine to edit" usually unblocks it.

**Q: Tool calls are failing or producing malformed JSON.**
A: Switch to a different model with `/model` — qwen handles tools more reliably than the others.

**Q: First response is slow, later ones are fast. Why?**
A: The model warms up after the first query. Later prompts in the same session reuse the loaded weights and KV cache.

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
