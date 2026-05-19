"""
Diagram Tools Module

Renders Mermaid diagrams via a self-hosted Kroki instance and posts the
resulting PNG into the current Webex room.

Kroki runs locally on lab-vm1 (see deployment/kroki/docker-compose.yml). The
base URL is configurable via the KROKI_BASE_URL env var (default:
http://localhost:8025).
"""

import logging
import os
import tempfile

import requests
from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

from my_config import get_config
from src.utils.tool_decorator import log_tool_call

FINAL_RESPONSE_PREFIX = "[FINAL_RESPONSE]"  # duplicated from state_manager to avoid circular import

logger = logging.getLogger(__name__)

CONFIG = get_config()

KROKI_BASE_URL = os.environ.get("KROKI_BASE_URL", "http://localhost:8025").rstrip("/")
KROKI_TIMEOUT_SECONDS = 20
MAX_MERMAID_SOURCE_CHARS = 8000

# ---------------------------------------------------------------------------
# Visual theme — injected into every Mermaid source. Pastel Material Design
# palette: soft fills with darker borders and dark text. Easy on the eyes
# for long viewing, prints well, and keeps subgraph backdrops subtle so the
# colored content inside breathes. Init directives merge in Mermaid 10+, so
# the LLM can still override individual variables if it really needs to.
# ---------------------------------------------------------------------------
THEME_INIT = (
    '%%{init: {"theme":"base",'
    # Curvy edges (basis spline) — gives flowing connectors between nodes,
    # especially nice for dotted reference lines from main flow to side panels.
    # htmlLabels:true is REQUIRED so the title node can use inline HTML
    # styling for big bold dark text.
    '"flowchart":{"curve":"basis","htmlLabels":true},'
    '"themeVariables":{'
    '"fontSize":"18px",'               # bigger than the ~14px Mermaid default
    '"primaryColor":"#e8eaf6",'        # light indigo node fill
    '"primaryTextColor":"#0f172a",'    # near-black text (max contrast)
    '"primaryBorderColor":"#283593",'  # darker indigo border
    '"lineColor":"#1e293b",'           # dark slate edges
    '"secondaryColor":"#e0f7fa",'      # light cyan
    '"tertiaryColor":"#fff8e1",'       # light amber
    '"background":"#ffffff",'
    '"mainBkg":"#e8eaf6",'
    '"secondBkg":"#e0f7fa",'
    '"tertiaryBkg":"#fff8e1",'
    # Sequence diagram knobs
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
    # Flowchart subgraph (cluster) styling — very light slate backdrop with
    # a clearly visible darker border so the outer "boxes with titles" stand
    # out as grouping containers without overpowering the inner nodes.
    '"clusterBkg":"#f8fafc",'
    '"clusterBorder":"#64748b",'
    '"titleColor":"#0f172a",'
    '"edgeLabelBackground":"#fff8e1"'
    '}}}%%\n'
)

# Reserved class names that the tool defines and the LLM should NOT redefine.
# If the model writes its own classDef for these names, we strip them so the
# brand palette is the only definition Kroki sees.
_RESERVED_CLASSES = {
    "attacker", "defender", "system", "external",
    "decision", "blocked", "success", "asset",
}

# Semantic classDef library — pastel Material Design fills with darker
# borders and dark text. Eight roles cover most security scenarios:
#   attacker (red), defender (green), system (indigo), external (cyan),
#   decision (amber), blocked (red, thick border), success (green, thick
#   border), asset (neutral slate).
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
    """Inject the brand theme (and classDefs for flowcharts) into Mermaid source.

    - Strips any leading %%{init}%% block the LLM may have written so our theme
      always wins (avoid two competing directives confusing Mermaid's parser).
    - Strips any classDef lines for our reserved class names so the LLM can't
      override the brand palette with washed-out definitions of its own.
    - Prepends THEME_INIT to every diagram regardless of type.
    - For flowchart/graph diagrams, wraps the entire body in an outer
      `subgraph OUTER[title]` with a thick dark border so the whole diagram
      sits inside one big container, then appends FLOWCHART_CLASSDEFS.
    """
    lines = source.splitlines()

    # Drop a leading init block if present (single line or multi-line)
    if lines and lines[0].lstrip().startswith("%%{init"):
        idx = 0
        while idx < len(lines) and not lines[idx].rstrip().endswith("%%"):
            idx += 1
        lines = lines[idx + 1:]

    # Strip leading blank lines
    while lines and not lines[0].strip():
        lines.pop(0)

    if not lines:
        return THEME_INIT + source  # nothing left after stripping; let Kroki error

    # Strip any classDef lines that redefine our reserved class names — keeps
    # user-defined custom classes intact while preventing palette conflicts.
    cleaned: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("classDef "):
            parts = stripped.split(None, 2)
            if len(parts) >= 2 and parts[1] in _RESERVED_CLASSES:
                continue  # drop the model's redefinition
        cleaned.append(line)
    lines = cleaned

    # Detect diagram type from first non-empty line
    first_line_lower = lines[0].strip().lower() if lines else ""
    is_flowchart = any(first_line_lower.startswith(t) for t in _FLOWCHART_TYPES)

    if is_flowchart:
        # Pull off the diagram type declaration line; everything after it gets
        # wrapped in the outer subgraph (Mermaid requires the type declaration
        # at the top, OUTSIDE any subgraph).
        type_line = lines[0]
        body_lines = lines[1:]

        # Extract the layout direction from the type line so we can mirror it
        # inside the outer subgraph (subgraphs don't inherit flowchart direction
        # automatically — they default to TB which would flip our LR layouts).
        type_tokens = type_line.strip().split()
        direction = "TB"
        if len(type_tokens) >= 2:
            candidate = type_tokens[1].upper()
            if candidate in ("LR", "RL", "TB", "TD", "BT"):
                direction = candidate

        # Sanitize the title — it goes inside an HTML <div> in the title
        # node label, so we HTML-escape and flatten whitespace. (Kroki strips
        # Mermaid's themeCSS, which rules out the cleaner frontmatter-title
        # approach — so we render the title as a styled flowchart node above
        # the OUTER subgraph, connected with an invisible `~~~` link.)
        import html as _html
        sanitized_title = (title or "Diagram").strip()
        sanitized_title = sanitized_title.replace("\n", " ").replace("\r", " ")
        sanitized_title = sanitized_title[:120]
        escaped_title = _html.escape(sanitized_title, quote=True)

        # Determine the outermost type keyword (`flowchart` or `graph`) so we
        # match what the LLM wrote — but force the outermost direction to TB
        # so the title node naturally sits above the OUTER subgraph. The
        # LLM's original direction is preserved INSIDE the OUTER subgraph.
        type_keyword = type_tokens[0] if type_tokens else "flowchart"

        title_node = (
            'TITLE["<div style=\'white-space:nowrap;padding:0 30px;'
            "font-size:28px;font-weight:bold;color:#0f172a'>"
            f"{escaped_title}"
            '</div>"]:::titleNode'
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
            # Thick dark border + white fill so the outer container reads as
            # a frame around the whole diagram, distinct from inner subgraphs.
            f"    style OUTER fill:#ffffff,stroke:#0f172a,stroke-width:5px,color:#0f172a\n"
            # titleNode is borderless/fillless so the title appears as
            # floating big bold text, not as a node with a box around it.
            f"    classDef titleNode fill:none,stroke:none\n"
        )
        return THEME_INIT + wrapped + FLOWCHART_CLASSDEFS

    body = "\n".join(lines)
    return THEME_INIT + body


def _get_current_room_id() -> str | None:
    """Extract room_id from the thread-local logging context.

    Same pattern as memory_tools._get_current_room_id — the session_key is
    set as "{user_id}_{room_id}" before tool execution in my_model.ask().
    """
    from src.utils.tool_logging import get_logging_context
    session_id = get_logging_context()
    if session_id and "_" in session_id:
        parts = session_id.split("_", 1)
        return parts[1] if len(parts) > 1 else None
    return None


@readonly_tool
@log_tool_call
def generate_diagram(mermaid_source: str, title: str = "") -> str:
    """
    Render a Mermaid diagram and post it as a PNG into the current Webex room.

    USE THIS TOOL when the user asks you to:
    - "Draw a diagram of ..."
    - "Visualize the attack flow / process / architecture"
    - "Make a flowchart / sequence diagram of ..."
    - "Show me a picture of how X works"
    - Any request that benefits from a structured visual (attack chains,
      control flows, system architectures, decision trees, timelines).

    The model is responsible for writing valid Mermaid syntax. Prefer:
      - `flowchart LR` or `flowchart TD` for attack chains and process flows
      - `sequenceDiagram` for message exchanges (e.g. SMTP, OAuth, API calls)
      - `graph TD` for hierarchies and decision trees

    A pastel brand theme is auto-injected — DO NOT write your own
    `%%{init}%%` block, the tool handles it. The classDef classes below are
    pre-defined by the tool — DO NOT redefine them in your source. The tool
    also wraps the entire flowchart in an outer thick-bordered container
    using the `title` argument as the container label, so pass a meaningful
    title.

    USE EMOJIS IN NODE LABELS for instant visual recognition. Kroki has the
    Noto Color Emoji font installed and renders them as full-color glyphs.
    Put the emoji at the START of the label, followed by a space and the
    text. Suggested mapping:
      🦹 attacker / threat actor       🛡️ security control / defense
      🌐 external / internet           📧 email / message
      📮 mail server                   📥 mailbox / inbox
      🖥️ endpoint / server             🔐 authentication
      ⚠️ warning / alert               🚫 blocked / rejected
      ❌ failure                       ✅ success
      🔍 inspection / scan / check     📨 notification / NDR
      🔥 firewall                      🏢 corporate network
      ☁️ cloud / SaaS                  💾 data / database

    LAYOUT — KEEP THE MAIN FLOW LINEAR, PUT CONTROLS ON THE SIDE:

    The main attack chain (attacker → transit hops → check → outcome) is
    ONE linear sequence connected by solid arrows `-->`. Security controls
    (DMARC/SPF/DKIM/EDR/firewall) go in a SEPARATE subgraph linked to the
    relevant decision node via DOTTED reference lines `-.->`. This makes
    Mermaid's dagre layout stack the controls subgraph above or below the
    main flow with curvy bezier connectors, instead of cramming everything
    into one horizontal row.

    NEVER wrap a single node in its own subgraph. Subgraphs are for groups
    of 2+ related nodes ONLY. A subgraph called "Recipient" containing one
    Yahoo node is wrong — put the node directly in the main chain with
    `:::external` and skip the subgraph.

    Worked example (correct shape):
        flowchart LR
            A[🦹 Attacker]:::attacker --> B[📮 Bell Canada]:::external
            B --> Y[🌐 Yahoo MX]:::external
            Y --> D{🔍 DMARC Check}:::decision
            D -->|❌ FAIL| R[🚫 Rejected 554]:::blocked
            R --> N[📨 NDR Bounce]:::asset
            N --> M[📥 <redacted-email>]:::system
            subgraph SC[🛡️ Security Controls]
                direction TB
                SC1[🛡️ DMARC Policy]:::defender
                SC2[🛡️ SPF Record]:::defender
                SC3[🛡️ DKIM Signature]:::defender
            end
            D -.-> SC1
            D -.-> SC2
            D -.-> SC3

    Notice: only ONE subgraph (Security Controls), three defender nodes
    inside it, dotted references from the DMARC decision node. The main
    chain is the linear sequence, the controls float beside it.

    Common groupings worth a subgraph: "Security Controls" (3+ defenders),
    "Internal Systems" (multiple corporate endpoints), "Detection"
    (SIEM/EDR/SOC alerting nodes). Single-purpose nodes belong in the
    main chain, NOT in their own subgraph.

    COLOR YOUR NODES SEMANTICALLY for impact:

    - For FLOWCHART/GRAPH diagrams, the tool defines these classes — apply
      them with `nodeId:::className` syntax:
        :::attacker  → red    (threat actors, malicious infra, IOCs)
        :::defender  → green  (security controls, EDR/SIEM/firewalls)
        :::system    → indigo (internal systems, endpoints, services)
        :::external  → cyan   (third-party / SaaS / cloud)
        :::decision  → amber  (decision points, checks, gates)
        :::blocked   → red    (blocked/failed/rejected states — thicker border)
        :::success   → green  (successful mitigations / clean states)
        :::asset     → slate  (data, files, neutral assets)

      Example:
        flowchart LR
            A[Attacker 50.x.x.x]:::attacker --> B[Bell Canada]:::external
            B --> Y[Yahoo MX]:::external
            Y --> D{DMARC Check}:::decision
            D -->|FAIL| R[Rejected 554 5.7.9]:::blocked
            R --> N[NDR Bounce]:::asset
            N --> M[<redacted-email>]:::system

    - For SEQUENCE diagrams, group actors by trust zone with `box` syntax:
        sequenceDiagram
            box rgb(254,226,226) External Threat
                participant A as Attacker
            end
            box rgb(199,210,254) the company
                participant M as User
            end

    Always start the source with the diagram type declaration. Do NOT wrap the
    source in markdown code fences — pass the raw Mermaid only.

    Args:
        mermaid_source: Raw Mermaid diagram source (no ``` fences, no init block).
        title: Optional short title shown above the diagram in Webex.

    Returns:
        Confirmation that the diagram was posted, or an error message.
    """
    if not mermaid_source or not mermaid_source.strip():
        return FINAL_RESPONSE_PREFIX + "Error: mermaid_source is empty."

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
        return FINAL_RESPONSE_PREFIX + (
            f"Error: diagram source is {len(source)} chars, exceeds "
            f"{MAX_MERMAID_SOURCE_CHARS}-char limit. Simplify the diagram."
        )

    room_id = _get_current_room_id()
    if not room_id:
        return FINAL_RESPONSE_PREFIX + (
            "Error: could not determine current Webex room. Diagram tool only "
            "works inside an active Webex conversation."
        )

    # Decorate with brand theme + (for flowcharts) outer container + classDefs
    decorated_source = _decorate_mermaid(source, title=title)

    # Render via Kroki
    render_url = f"{KROKI_BASE_URL}/mermaid/png"
    try:
        resp = requests.post(
            render_url,
            data=decorated_source.encode("utf-8"),
            headers={"Content-Type": "text/plain"},
            timeout=KROKI_TIMEOUT_SECONDS,
        )
    except requests.RequestException as e:
        logger.error(f"Kroki request failed: {e}")
        return FINAL_RESPONSE_PREFIX + (
            f"Error: could not reach Kroki at {KROKI_BASE_URL}. "
            f"The diagram service may be down. ({e})"
        )

    if resp.status_code != 200:
        # Kroki returns the parser error in the body on 400
        body = resp.text[:500] if resp.text else ""
        logger.error(f"Kroki render failed (HTTP {resp.status_code}): {body}")
        return FINAL_RESPONSE_PREFIX + (
            f"Error: Kroki rejected the diagram (HTTP {resp.status_code}). "
            f"The Mermaid syntax is likely invalid. Details: {body}"
        )

    if not resp.content or len(resp.content) < 100:
        return FINAL_RESPONSE_PREFIX + "Error: Kroki returned an empty image."

    # Write PNG to a temp file so the Webex SDK uploads bytes (not a URL)
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".png", prefix="diagram_", delete=False
        ) as tmp:
            tmp.write(resp.content)
            tmp_path = tmp.name
    except OSError as e:
        logger.error(f"Failed to write diagram tempfile: {e}")
        return FINAL_RESPONSE_PREFIX + f"Error: could not save diagram locally ({e})."

    try:
        from webexpythonsdk import WebexAPI
        webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_pokedex)
        message_text = title.strip() if title and title.strip() else "📊 Diagram"
        webex_api.messages.create(
            roomId=room_id,
            text=message_text,
            files=[tmp_path],
        )
        logger.info(
            f"Posted diagram to room {room_id[:12]}... "
            f"({len(resp.content)} bytes, title={title!r})"
        )
        return FINAL_RESPONSE_PREFIX + (
            f"✅ Diagram posted ({len(resp.content)} bytes)."
        )
    except Exception as e:
        logger.error(f"Failed to post diagram to Webex: {e}", exc_info=True)
        return FINAL_RESPONSE_PREFIX + f"Error: could not post diagram to Webex ({e})."
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
