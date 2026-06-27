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

### Watch → gate
On a clock-aligned cadence, the watcher reads new human messages and runs a
single lightweight relevance pass to decide which ones are actually security
questions worth acting on — batched into one call per tick to stay cheap.

### Auto-run the safe ones
A question that only needs read-only lookups (a status check, an enrichment, an
asset lookup) is run automatically and the answer is posted back. A thread-local
guard hard-denies every state-changing tool during an auto-run, so an
un-requested action can never fire — no matter who asked.

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
