---
layout: doc
title: Ambient Assistant
---

# Ambient Assistant

A proactive layer on the chat assistant: instead of waiting to be @-mentioned,
it quietly watches a SOC room, notices when someone asks a security question,
answers the read-only ones on its own, and offers a one-click card for anything
that would change state.

---

## Why this exists

The reactive assistant is great when you remember to call it. But in a busy room
most questions never get directed at the bot — someone asks "what's the
containment status of that host?" to the room, and it either gets answered by
hand or not at all. A senior analyst reading the room would just answer the easy
ones and flag the risky ones. That's the behavior this models.

---

## What it does

### Watch → gist
On a clock-aligned cadence, the watcher reads the new human messages and runs a
single pass over the whole window — not message-by-message — to synthesize what
the room actually *needs*: the open security questions, who they're about, and
what would answer them. One batched call per tick keeps it cheap, and a dedup
guard means a need that was just answered won't be re-raised on the next tick.

### See the screenshots
Analysts paste screenshots, not transcripts. When a relevant image shows up, the
watcher runs it through the vision model (OCR + IOC extraction) and inlines the
read-back into the lookup — so "is this IP malicious?" under a pasted alert gets
answered from what the picture actually says, not ignored for lack of text.

### Auto-run the safe ones
A need that only takes read-only lookups (a status check, an enrichment, an
asset lookup) is run automatically and the answer is posted back. A thread-local
guard hard-denies every state-changing tool during an auto-run, so an
un-requested action can never fire — no matter who asked.

### Stay in the thread
Answers post under the asker's own message, and the watcher remembers the
context, so a follow-up like "what about his email?" or "and her manager?"
resolves against the right person instead of starting cold. A short intent pass
tells a genuine follow-up apart from a fresh question.

### Card the risky ones
Anything with blast radius — block, isolate, contain, close — isn't run.
Instead the watcher posts a human-in-the-loop **"Run it"** card. The action only
executes when a human clicks it, and it runs with *that person's* capabilities,
re-using the same role-gated path as a normal request. Cards are single-use, so
two people can't double-fire the same action.

### Read identity
Group-room messages aren't visible to a bot token, so the watcher reads through
an OAuth identity scoped to message-read — the same reason its proactive replies
post under a clearly-attributed automated identity rather than impersonating a
person.

---

## Safety model

The split is the whole point: **reads auto-run, writes wait for a human.** The
relevance gate decides *whether* to engage; the read-only guard decides *what
may run unattended*; and the capability check on the card click decides *who may
act*. Every consequential step keeps a person in the loop.
