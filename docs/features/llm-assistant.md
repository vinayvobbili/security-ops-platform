---
layout: default
title: LLM-Powered Security Assistant
---

# LLM-Powered Security Assistant

An AI investigation engine that augments SOC analyst capabilities through natural language interaction and automated tool orchestration.

---

## Overview

The security assistant uses **Retrieval-Augmented Generation (RAG)** to combine LLM intelligence with real-time security data from 22 integrated tools. Analysts can ask questions in natural language and receive enriched, contextual responses.

### Key Capabilities

- **Natural Language Queries**: Ask security questions without learning tool syntax
- **Multi-Tool Orchestration**: Automatically selects and chains appropriate tools
- **Context-Aware Responses**: RAG retrieves relevant documentation and history
- **Continuous Learning**: Knowledge base expands with new runbooks and procedures

---

## Investigation Tools (22)

### Endpoint Detection & Response

| Tool | Capabilities |
|------|--------------|
| **CrowdStrike Host Lookup** | Query endpoint details, sensor status, containment state |
| **CrowdStrike Detection Search** | Find detections by host, severity, time range |
| **CrowdStrike Containment** | Network isolate/release hosts |
| **Tanium Endpoint Status** | Real-time endpoint health and compliance |
| **Tanium Live Query** | Execute ad-hoc endpoint queries |

### SIEM & Log Analysis

| Tool | Capabilities |
|------|--------------|
| **QRadar Log Search** | Query logs across all sources |
| **QRadar AQL Query** | Advanced Ariel Query Language searches |
| **QRadar Offense Investigation** | Investigate correlated offenses |

### Threat Intelligence

| Tool | Capabilities |
|------|--------------|
| **Recorded Future** | Risk scores, threat context, related indicators |
| **VirusTotal** | Hash, URL, domain reputation from 70+ engines |
| **URLScan** | Website scanning and screenshot capture |
| **AbuseIPDB** | IP reputation and abuse reports |
| **Shodan** | Internet-facing asset discovery |
| **IntelX** | Dark web and leak database search |

### Identity, Email & Workflow

| Tool | Capabilities |
|------|--------------|
| **Have I Been Pwned** | Email breach checking |
| **ServiceNow** | CMDB queries, ticket creation |
| **Abnormal Security** | Email threat investigation |
| **Zscaler** | URL categorization |
| **XSOAR** | Incident management |

---

## How It Works

1. **User Query**: Analyst asks a question in natural language
2. **RAG Retrieval**: System retrieves relevant runbooks and context
3. **Tool Selection**: LLM determines which tools to invoke
4. **Execution**: Tools query security platforms in parallel
5. **Synthesis**: LLM combines results into actionable response

---

## Technical Implementation

- **Framework**: LangChain with native tool binding
- **LLM**: Ollama (local inference)
- **Vector Store**: ChromaDB for document embeddings
- **Pattern**: Simple @tool decorators, no complex orchestration

---

[← Back to Features](index) | [View Bot Architecture →](webex-bots)
