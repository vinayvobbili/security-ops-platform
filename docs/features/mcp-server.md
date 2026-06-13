---
layout: doc
title: MCP Server
---

# Model Context Protocol (MCP) Server

A standalone Model Context Protocol server that exposes the platform's full security toolbox to any MCP-compatible client — Claude Desktop, Cline, Continue, or any agent framework that speaks MCP.

---

## Overview

The MCP server lives in `mcp_server/` and ships **31 security tools** behind a single uniform schema. Drop the server into your MCP client config and the agent gets immediate access to EDR queries, SIEM searches, threat-intel lookups, ticket creation, identity lookups, and more — without writing a single integration.

### Why MCP?

The Model Context Protocol standardizes how LLM clients talk to tools. By exposing the same security toolset both through the platform's internal LangChain agents *and* through MCP, the underlying tool implementations stay DRY — one source of truth, two consumption surfaces.

---

## Tools (31)

### Endpoint Detection & Response
| Tool | Capability |
|---|---|
| `crowdstrike` | Host lookup, detection search, containment, IOC management |
| `tanium` | Endpoint queries, sensor status, live response |

### SIEM & Logs
| Tool | Capability |
|---|---|
| `qradar` | Log search, AQL queries, offense investigation |

### Case Management & SOAR
| Tool | Capability |
|---|---|
| `xsoar` | Ticket lookup, enrichment, summary generation |
| `dfir_iris` | Case creation, IOC management, timeline events |
| `the_hive` | Case management, observables, alert handling |
| `service_now` | CMDB queries, ticket creation, change management |

### Threat Intelligence
| Tool | Capability |
|---|---|
| `virustotal` | Hash, URL, domain reputation |
| `urlscan` | Website scanning, screenshots, DOM capture |
| `abuseipdb` | IP reputation and abuse reports |
| `abusech` | Malware Bazaar, ThreatFox, URLhaus |
| `intelx` | Dark web and leak database search |
| `shodan` | Internet-facing asset discovery |
| `hibp` | Email breach checking |
| `recorded_future` | Risk scores, threat context, related indicators |

### Email & Web Security
| Tool | Capability |
|---|---|
| `abnormal` | Email threat investigation |
| `block_url` | Push URL blocks to upstream filtering |

### Identity
| Tool | Capability |
|---|---|
| `active_directory` | User and group lookups |

### BAS / Validation
| Tool | Capability |
|---|---|
| `attackiq` | Attack simulation results, control-efficacy data |

### Utility
| Tool | Capability |
|---|---|
| `contacts` | Internal contact directory lookup |
| `diagrams` | On-demand architecture/flow diagram generation |
| `... and more` | Domain monitoring, threat-intel correlation, IOC enrichment |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              MCP Client (Claude Desktop, Cline, ...)     │
└────────────────────────────┬─────────────────────────────┘
                             │ MCP protocol (stdio / sse)
                             ▼
┌──────────────────────────────────────────────────────────┐
│                     FastMCP Server                       │
│   ┌──────────────────────────────────────────────────┐   │
│   │  Tool Registry  ·  Schema  ·  Auth  ·  Logging   │   │
│   └──────────────────────────────────────────────────┘   │
│                            │                             │
│                            ▼                             │
│   ┌──────────────────────────────────────────────────┐   │
│   │   31 Tool implementations (mcp_server/tools/*.py)│   │
│   └──────────────────────────────────────────────────┘   │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│           Shared services/ API clients                   │
│      (the same clients used by web app + agents)         │
└──────────────────────────────────────────────────────────┘
```

The MCP server is a thin shell over the platform's existing service clients. Each tool file in `mcp_server/tools/` registers one or more MCP tools, each delegating to a service-layer client. That keeps tool schemas consistent and means a fix in the underlying client (e.g. retry-on-429) instantly benefits both consumption paths.

---

## Connecting an MCP client

### Claude Desktop

Add the server to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-ops": {
      "command": "python",
      "args": ["-m", "mcp_server"],
      "cwd": "/path/to/security-ops-platform",
      "env": {
        "PYTHONPATH": "/path/to/security-ops-platform"
      }
    }
  }
}
```

### Cline / Continue

Same idea — point at `python -m mcp_server` with the repo as the working directory. The server reads credentials from the same `.env` the rest of the platform uses, so configuring it once configures it everywhere.

---

## Tool design principles

1. **One source of truth.** Tools delegate to `services/` clients; never re-implement an API call inside an MCP tool.
2. **Schema-first.** Every tool exposes a clean Pydantic-typed schema so agents can introspect and self-correct.
3. **Stateless.** Tools don't carry session state; everything needed is in the request.
4. **Bounded output.** Long results are summarized or paginated to keep token budgets sane.

---

[← Back to Features](index)
