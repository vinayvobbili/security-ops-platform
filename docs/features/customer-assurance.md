---
layout: default
title: Customer Assurance Workspace
---

# Customer Assurance Workspace

Web-based intake plus LLM-assisted drafting for customer security questionnaires. Routes incoming requests through a queue, generates first-pass answers grounded in your existing controls knowledge base, and lets reviewers refine before export.

---

## The problem

Vendor security questionnaires are a tax on security teams: 100–300 question Excel files, half of them duplicates of last quarter's questionnaire, all of them needing a human to write a careful answer that aligns with policy. The customer assurance workspace cuts the busywork by:

- Standardizing intake (one form, structured fields, clean queue)
- Drafting answers from the controls knowledge base
- Letting reviewers focus only on the parts that need human judgment
- Exporting back to whatever format the customer wanted

---

## Workflow

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ Sales /  │──▶│  Intake  │──▶│   LLM    │──▶│ Reviewer │──▶│  Export  │
│ Account  │   │   Form   │   │  Draft   │   │  Refine  │   │   Doc    │
└──────────┘   └──────────┘   └──────────┘   └──────────┘   └──────────┘
                    │              │              │              │
                    ▼              ▼              ▼              ▼
                  Queue        Knowledge       Workspace      Customer
                  page         base (RAG)      page           format
```

### 1. Intake
Sales or account management drops the questionnaire (and customer context) into the intake form. The submission lands in a queue page where the security team triages.

### 2. Draft
For each question, the LLM retrieves the most relevant entries from the controls knowledge base and produces a first-pass answer with cited sources. The intent isn't to replace the reviewer — it's to skip the 70% of answers that are mechanical lookups.

### 3. Refine
Reviewers work in the workspace page: each question shows the draft, the retrieved context, and a free-form editor. Accepting or revising is one click. Questions that need policy input get flagged.

### 4. Export
Once reviewed, the workspace exports the responses back into a format the customer can ingest (CSV, Excel, or filled-in template).

---

## Pages

| Page | Purpose |
|---|---|
| **Landing** | Overview, queue counts, recent activity |
| **Intake form** | Submit a new questionnaire with customer context |
| **Queue** | Triage incoming requests, assign reviewers |
| **Workspace** | Question-by-question drafting and review |
| **Knowledge base** | Browse / edit the controls answer library |

---

## Knowledge base

The KB is a structured store of canonical answers grouped by control family (access control, encryption, incident response, vendor management, etc.). Each entry has:

- The answer text
- Linked policy / standard references
- Last-reviewed timestamp
- Tags for retrieval

The LLM uses RAG over this store. When sources go stale or a customer asks something new, the answer gets back-written into the KB so the next questionnaire benefits.

---

## Why an LLM helps here

Questionnaires are repetitive in *content* but variable in *phrasing*. Customers ask "Do you encrypt data at rest?" forty different ways. Keyword matching in a spreadsheet of past answers is brittle; semantic retrieval handles paraphrase well. The LLM draft is a starting point — what the reviewer accepts or rewrites becomes the next training signal for the KB.

---

[← Back to Features](index)
