---
layout: doc
title: Security Training & Readiness
---

# Security Training & Readiness

Interactive analyst training that ends in a graded readiness check. Each topic
pairs a short lesson with a quiz that's drawn fresh every attempt, grades open
answers on understanding rather than wording, and issues a verifiable
completion certificate when the analyst passes.

---

## Why this exists

Most security training is a slide deck and a multiple-choice quiz everyone
shares the answer key to. This flips both halves: lessons read like a teammate
explaining attacker tradecraft and the detection signals that matter, and the
quiz is sampled from a bank deep enough that two analysts rarely see the same
test — so passing means knowing the material, not memorizing an answer key.

---

## What it does

### Prep pages
Each topic has its own page: a generated training video, a plain-language
"why it's risky," and the key concepts laid out as an attacker kill-chain with
the detection signals and analyst actions at each stage.

### Fresh, mixed-format quizzes
Every attempt samples and shuffles a new test from the topic's question bank
across five formats — multiple choice, fill-in-the-blank, drag-and-drop
match-the-following, short answer, and free response. The sampler spreads a test
across distinct concepts so the same idea doesn't repeat three times in one
attempt. Closed formats are graded deterministically — fill-in-the-blank forgives
typos via bounded edit distance (while still holding short codes exact); open
answers are scored 0..1 with feedback by the local LLM, crediting the right
understanding in the analyst's own words. Harder questions are worth more (easy
1 / medium 2 / hard 3 points). 60% passes, 80% earns a distinction.

### Decision-first lessons
Questions read like a live incident — given this telemetry, alert, or situation,
what do you conclude and what do you do next — instead of vocabulary recall. The
catalog and lesson reading are open to everyone; only the graded quiz and the
certificate require an account.

### Completion certificate
Passing issues a branded certificate as both a web page and a downloadable PDF,
carrying a tamper-evident verification code derived from the learner, topic,
score, and award date — change any detail and the code no longer matches.

### Time limit + anti-cheat
A 45-minute countdown auto-submits whatever's answered when it hits zero, and a
deterministic fast-pass check flags passes completed implausibly faster than it
takes to genuinely read and answer the questions.

### Admin command center
A per-lesson analytics view tracks completion, distinction rates, and
week-over-week trends, surfaces integrity flags, and exports to Excel.

### Question-bank generator
A generator drafts new questions grounded strictly in a topic's own material,
validates and de-duplicates them, and appends to the bank — so a topic's test
pool keeps deepening without hand-authoring hundreds of questions.

---

## Under the hood

Generation, mixed-format sampling, deterministic + LLM grading, and the
integrity / time-limit policy all delegate to the open-source
[`quizforge`](https://pypi.org/project/quizforge/) core. The application layer
is a thin seam that supplies the local LLM and the SOC-specific framing, so the
training engine itself stays vendor-neutral and reusable.

---

[← Back to Features](/features/)
