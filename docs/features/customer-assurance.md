---
layout: doc
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
Sales or account management drops the questionnaire (and customer context) into the intake form. Uploaded `.xlsx` files are auto-parsed: each sheet is scanned for a question column (a `Question` / `Question Text` / `Assessment Question` header, or — when the vendor template skips that label — the column immediately to the left of `Vendor Response`). Section headers like `Sub Domain`, `Control Category`, or `Privacy Domain` are preserved, and the source sheet/row/response-column for each question is recorded so the export step can write answers back into the original spreadsheet. PDFs and Word docs still require pasting the text. The submission lands in a queue page where the security team triages.

### 2. Draft
For each question, the LLM retrieves the most relevant entries from the controls knowledge base and produces a first-pass answer with cited sources. The intent isn't to replace the reviewer — it's to skip the 70% of answers that are mechanical lookups.

### 3. Refine
Reviewers work in the workspace page: each question shows the draft, the retrieved context, and a free-form editor. Accepting or revising is one click. Questions that need policy input get flagged.

### 4. Export
Once reviewed, the workspace exports the responses. When the questionnaire was uploaded as `.xlsx`, the export round-trips: a copy of the customer's original spreadsheet is written with each final answer placed at the same `(sheet, row, response_col)` the question was extracted from. Empty answers leave the original cell untouched rather than being overwritten with placeholder text, so partial responses ship cleanly. Pasted-text intakes (no source coords) fall back to a `.docx` export.

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
