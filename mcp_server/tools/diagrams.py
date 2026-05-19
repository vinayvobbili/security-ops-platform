"""Diagram rendering tools via Kroki (Mermaid → PNG) posted to Webex."""

import logging
import os
import tempfile

import requests

from mcp_server.server import mcp

logger = logging.getLogger(__name__)

KROKI_BASE_URL = os.environ.get("KROKI_BASE_URL", "http://localhost:8025").rstrip("/")
KROKI_TIMEOUT_SECONDS = 20
MAX_MERMAID_SOURCE_CHARS = 8000

# ---------------------------------------------------------------------------
# Visual theme — injected into every Mermaid source.
# Pastel Material Design palette with dark text. Matches Pokedex diagrams.
# ---------------------------------------------------------------------------
THEME_INIT = (
    '%%{init: {"theme":"base",'
    '"flowchart":{"curve":"basis","htmlLabels":true},'
    '"themeVariables":{'
    '"fontSize":"18px",'
    '"primaryColor":"#e8eaf6",'
    '"primaryTextColor":"#0f172a",'
    '"primaryBorderColor":"#283593",'
    '"lineColor":"#1e293b",'
    '"secondaryColor":"#e0f7fa",'
    '"tertiaryColor":"#fff8e1",'
    '"background":"#ffffff",'
    '"mainBkg":"#e8eaf6",'
    '"secondBkg":"#e0f7fa",'
    '"tertiaryBkg":"#fff8e1",'
    '"actorBkg":"#e8eaf6",'
    '"actorBorder":"#283593",'
    '"actorTextColor":"#0f172a",'
    '"actorLineColor":"#94a3b8",'
    '"signalColor":"#0f172a",'
    '"signalTextColor":"#0f172a",'
    '"labelBoxBkgColor":"#fff8e1",'
    '"labelBoxBorderColor":"#ffa000",'
    '"labelTextColor":"#0f172a",'
    '"loopTextColor":"#0f172a",'
    '"noteBkgColor":"#fff8e1",'
    '"noteBorderColor":"#ffa000",'
    '"noteTextColor":"#0f172a",'
    '"activationBkgColor":"#e8eaf6",'
    '"activationBorderColor":"#283593",'
    '"sequenceNumberColor":"#0f172a",'
    '"clusterBkg":"#f8fafc",'
    '"clusterBorder":"#64748b",'
    '"titleColor":"#0f172a",'
    '"edgeLabelBackground":"#fff8e1"'
    '}}}%%\n'
)

_RESERVED_CLASSES = {
    "attacker", "defender", "system", "external",
    "decision", "blocked", "success", "asset",
}

FLOWCHART_CLASSDEFS = (
    "    classDef attacker fill:#ffebee,stroke:#c62828,stroke-width:2.5px,color:#0f172a,font-weight:bold\n"
    "    classDef defender fill:#e8f5e9,stroke:#2e7d32,stroke-width:2.5px,color:#0f172a,font-weight:bold\n"
    "    classDef system fill:#e8eaf6,stroke:#283593,stroke-width:2.5px,color:#0f172a,font-weight:bold\n"
    "    classDef external fill:#e0f7fa,stroke:#006064,stroke-width:2.5px,color:#0f172a,font-weight:bold\n"
    "    classDef decision fill:#fff8e1,stroke:#ffa000,stroke-width:2.5px,color:#0f172a,font-weight:bold\n"
    "    classDef blocked fill:#ffebee,stroke:#c62828,stroke-width:3.5px,color:#0f172a,font-weight:bold\n"
    "    classDef success fill:#e8f5e9,stroke:#2e7d32,stroke-width:3.5px,color:#0f172a,font-weight:bold\n"
    "    classDef asset fill:#eceff1,stroke:#455a64,stroke-width:2.5px,color:#0f172a,font-weight:bold\n"
)

_FLOWCHART_TYPES = ("flowchart", "graph")


def _decorate_mermaid(source: str, title: str = "") -> str:
    """Inject brand theme and classDefs into Mermaid source."""
    lines = source.splitlines()

    # Drop a leading init block if present
    if lines and lines[0].lstrip().startswith("%%{init"):
        idx = 0
        while idx < len(lines) and not lines[idx].rstrip().endswith("%%"):
            idx += 1
        lines = lines[idx + 1:]

    while lines and not lines[0].strip():
        lines.pop(0)

    if not lines:
        return THEME_INIT + source

    # Strip classDef lines that redefine reserved class names
    cleaned: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("classDef "):
            parts = stripped.split(None, 2)
            if len(parts) >= 2 and parts[1] in _RESERVED_CLASSES:
                continue
        cleaned.append(line)
    lines = cleaned

    first_line_lower = lines[0].strip().lower() if lines else ""
    is_flowchart = any(first_line_lower.startswith(t) for t in _FLOWCHART_TYPES)

    if is_flowchart:
        type_line = lines[0]
        body_lines = lines[1:]
        type_tokens = type_line.strip().split()
        direction = "TB"
        if len(type_tokens) >= 2:
            candidate = type_tokens[1].upper()
            if candidate in ("LR", "RL", "TB", "TD", "BT"):
                direction = candidate

        import html as _html
        sanitized_title = (title or "Diagram").strip()[:120]
        sanitized_title = sanitized_title.replace("\n", " ").replace("\r", " ")
        escaped_title = _html.escape(sanitized_title, quote=True)
        type_keyword = type_tokens[0] if type_tokens else "flowchart"

        title_node = (
            'TITLE["<div style=\'white-space:nowrap;padding:0 30px;'
            "font-size:28px;font-weight:bold;color:#0f172a'>"
            f"{escaped_title}</div>\"]:::titleNode"
        )
        indented = "\n".join("    " + line if line.strip() else line for line in body_lines)
        wrapped = (
            f"{type_keyword} TB\n"
            f"    {title_node}\n"
            f"    TITLE ~~~ OUTER\n"
            f'    subgraph OUTER[" "]\n'
            f"        direction {direction}\n"
            f"{indented}\n"
            f"    end\n"
            f"    style OUTER fill:#ffffff,stroke:#0f172a,stroke-width:5px,color:#0f172a\n"
            f"    classDef titleNode fill:none,stroke:none\n"
        )
        return THEME_INIT + wrapped + FLOWCHART_CLASSDEFS

    return THEME_INIT + "\n".join(lines)


@mcp.tool(tags={"readonly"})
def render_diagram(
    mermaid_source: str,
    room_id: str,
    title: str = "",
    parent_id: str = "",
) -> dict:
    """Render a Mermaid diagram as PNG and post it to a Webex room.

    Renders the diagram via the local Kroki instance and posts the PNG image
    directly into the specified Webex room/thread.

    IMPORTANT: Always pass the room_id and parent_id from the current conversation
    context. These are provided in the system prompt for every conversation.

    Diagram types and class names for security diagrams:
    - flowchart LR / TD — attack chains, process flows, architectures
    - sequenceDiagram — SMTP exchanges, OAuth flows, API call traces
    - graph TD — decision trees, hierarchies

    Node classes (flowchart/graph only):
      :::attacker  red    — threat actors, malicious infra
      :::defender  green  — security controls, EDR/SIEM/firewalls
      :::system    indigo — internal systems, endpoints
      :::external  cyan   — third-party / SaaS / cloud
      :::decision  amber  — decision points, checks
      :::blocked   red    — blocked/rejected states
      :::success   green  — clean/allowed states
      :::asset     slate  — data, files, neutral assets

    Args:
        mermaid_source: Raw Mermaid source (no ``` fences, no %%{init}%% block)
        room_id: Webex room ID to post the diagram into
        title: Optional title shown above the diagram (default: 'Diagram')
        parent_id: Optional thread parent message ID for threaded reply
    """
    if not mermaid_source or not mermaid_source.strip():
        return {"success": False, "error": "mermaid_source is empty"}

    if not room_id or not room_id.strip():
        return {"success": False, "error": "room_id is required"}

    source = mermaid_source.strip()
    # Strip accidental code fences
    if source.startswith("```"):
        lines = source.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        source = "\n".join(lines).strip()

    if len(source) > MAX_MERMAID_SOURCE_CHARS:
        return {
            "success": False,
            "error": f"Diagram source is {len(source)} chars, exceeds {MAX_MERMAID_SOURCE_CHARS}-char limit. Simplify.",
        }

    decorated = _decorate_mermaid(source, title=title)

    # Render via Kroki
    try:
        resp = requests.post(
            f"{KROKI_BASE_URL}/mermaid/png",
            data=decorated.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            timeout=KROKI_TIMEOUT_SECONDS,
        )
    except requests.RequestException as e:
        logger.error(f"Kroki request failed: {e}")
        return {"success": False, "error": f"Kroki unavailable at {KROKI_BASE_URL}: {e}"}

    if resp.status_code != 200:
        body = resp.text[:500] if resp.text else ""
        logger.error(f"Kroki render failed (HTTP {resp.status_code}): {body}")
        return {"success": False, "error": f"Kroki rejected diagram (HTTP {resp.status_code}): {body}"}

    if not resp.content or len(resp.content) < 100:
        return {"success": False, "error": "Kroki returned an empty image"}

    # Save to temp file and post to Webex
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".png", prefix="diagram_", delete=False) as tmp:
            tmp.write(resp.content)
            tmp_path = tmp.name

        from my_config import get_config
        from webexpythonsdk import WebexAPI

        config = get_config()
        webex_api = WebexAPI(access_token=config.webex_bot_access_token_barnacles)

        kwargs = {
            "roomId": room_id,
            "text": title.strip() if title and title.strip() else "📊 Diagram",
            "files": [tmp_path],
        }
        if parent_id and parent_id.strip():
            kwargs["parentId"] = parent_id.strip()

        webex_api.messages.create(**kwargs)
        logger.info(f"Posted diagram to room {room_id[:12]}... ({len(resp.content)} bytes)")
        return {"success": True, "bytes": len(resp.content), "message": "Diagram posted to Webex."}

    except Exception as e:
        logger.error(f"Failed to post diagram to Webex: {e}", exc_info=True)
        return {"success": False, "error": f"Could not post diagram to Webex: {e}"}
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
