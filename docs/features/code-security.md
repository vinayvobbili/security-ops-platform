---
layout: doc
title: Code Security Scanner
---

# Code Security Scanner

An agentic, read-only vulnerability audit of a code repository: point it at a
repo, and a pair of LLM passes navigate the tree, surface candidate findings,
and then argue against each one before it ever reaches you.

---

## Why this exists

Most code scanners drown you in findings — and most of those findings are
false. The expensive part of using a scanner isn't running it, it's triaging
the noise. This tool flips the default: a finding only survives if a second,
adversarial pass **fails to refute it**. You get a short list you can trust
instead of a long list you have to disprove.

---

## What it does

### Navigate → enumerate
A local LLM walks the repository the way a reviewer would — following imports,
reading the risky surfaces (auth, input handling, deserialization, subprocess,
SQL, secrets) — and proposes candidate vulnerabilities with file/line context.

### Refute → confirm
Each candidate is handed to a second pass that is told to **break it**: prove
the finding is wrong, unreachable, or already mitigated. Only candidates that
survive the refutation are reported. The structured verdict carries a rationale,
so every kept finding comes with the argument for why it's real.

### Container-jailed
The scan clones and runs inside a throwaway, network-restricted container — the
audited code never executes against the host, and nothing the repo brings with
it can reach out.

### Engine seam
The two-pass engine is delegated to the open
[`refutescan`](https://pypi.org/project/refutescan/) package, so the scanning
kernel is model-agnostic and reusable outside this platform; the app just wires
in its LLM and presents the results.

---

## Access

The page is open to view; running a scan requires sign-in. Results are kept per
run so you can return to a previous audit.
