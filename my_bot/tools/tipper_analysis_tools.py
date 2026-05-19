"""
Tipper Analysis Tools Module

Tools for analyzing threat tippers for novelty against historical data.
"""

import logging
import re
from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool

FINAL_RESPONSE_PREFIX = "[FINAL_RESPONSE]"  # duplicated from state_manager to avoid circular import
from my_config import get_config
from src.components.tipper_analyzer import TIPPER_ANALYSIS_ROOM_ID, IOC_HUNT_ROOM_ID
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

CONFIG = get_config()


def _linkify_work_items(text: str, org: str, project: str) -> str:
    """Convert work item references like #12345 to Azure DevOps HTML hyperlinks."""
    def replace_match(match):
        work_item_id = match.group(1)
        url = f"https://dev.azure.com/{org}/{project}/_workitems/edit/{work_item_id}"
        return f'<a href="{url}">#{work_item_id}</a>'

    return re.sub(r'#(\d+)', replace_match, text)


def _linkify_work_items_markdown(text: str, org: str, project: str) -> str:
    """Convert work item references like #12345 to markdown hyperlinks for Webex."""
    def replace_match(match):
        work_item_id = match.group(1)
        url = f"https://dev.azure.com/{org}/{project}/_workitems/edit/{work_item_id}"
        return f'[#{work_item_id}]({url})'

    return re.sub(r'#(\d+)', replace_match, text)


def _markdown_to_html(text: str) -> str:
    """Convert markdown-style formatting to HTML for Azure DevOps comments."""
    # Convert **bold** to <strong>bold</strong>
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)

    # Convert newlines to <br> tags for proper line breaks
    text = text.replace('\n', '<br>\n')

    return text


@readonly_tool
@log_tool_call
def analyze_tipper_novelty(tipper_id: str) -> str:
    """
    Analyze a threat tipper for novelty against historical tippers.

    USE THIS TOOL when users ask:
    - "Analyze tipper 12345"
    - "Is tipper 12345 new?"
    - "What's novel about tipper 12345?"
    - "Have we seen tipper 12345 before?"
    - "Check tipper 12345 against history"
    - "How new is this tipper?"
    - "Compare tipper to past tippers"
    - "Analyze tipper 12345 and post to AZDO"

    This tool:
    1. Fetches the tipper from Azure DevOps
    2. Searches for similar historical tippers using vector similarity
    3. Uses AI to analyze novelty and identify what's new vs familiar
    4. Returns a novelty score (1-10) and actionable recommendation
    5. Posts the full analysis as a comment on the AZDO work item
    6. Kicks off IOC hunt in the background

    Args:
        tipper_id: The Azure DevOps work item ID for the tipper (e.g., "12345")

    Returns:
        Formatted analysis with novelty score, what's new, what's familiar,
        related tickets, and recommendation (PRIORITIZE/STANDARD/EXPEDITE)
    """
    try:
        from src.components.tipper_analyzer import TipperAnalyzer
        from my_config import get_config

        logger.info(f"Analyzing tipper #{tipper_id} for novelty...")

        analyzer = TipperAnalyzer()

        # Full flow: analyze + post to AZDO + send analysis to tipper room
        # + background IOC hunt + background CVE exposure correlation.
        # The Webex send to the tipper analysis room happens inside
        # analyze_and_post (so the exposure follow-up can reply-thread to it).
        analyzer.analyze_and_post(
            tipper_id, source="tool", room_id=IOC_HUNT_ROOM_ID
        )
        config = get_config()
        azdo_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_de_project}/_workitems/edit/{tipper_id}"

        # Return minimal confirmation — FINAL_RESPONSE skips redundant LLM iteration
        return FINAL_RESPONSE_PREFIX + f"✅ Analysis written to tipper #{tipper_id}\n🔗 [View Tipper in AZDO]({azdo_url})"

    except ValueError as e:
        logger.error(f"Tipper not found: {e}")
        return FINAL_RESPONSE_PREFIX + f"Error: Tipper #{tipper_id} not found in the Threat Hunting area. Please verify the tipper ID is correct and belongs to Threat Hunting."

    except RuntimeError as e:
        logger.error(f"Analysis failed: {e}")
        if "index" in str(e).lower():
            return FINAL_RESPONSE_PREFIX + (
                f"Error: Tipper similarity index not available. "
                f"The index may need to be built first. Please contact an admin."
            )
        return FINAL_RESPONSE_PREFIX + f"Error analyzing tipper: {str(e)}"

    except Exception as e:
        logger.error(f"Error analyzing tipper {tipper_id}: {e}", exc_info=True)
        return FINAL_RESPONSE_PREFIX + f"Error analyzing tipper: {str(e)}"


@mutating_tool
@log_tool_call
def add_note_to_tipper(tipper_id: str, note: str) -> str:
    """
    Add a note/comment to an Azure DevOps tipper.

    USE THIS TOOL when users ask:
    - "Add note to tipper 12345: [note text]"
    - "Comment on tipper 12345: [note text]"
    - "Write on tipper 12345 that these are known TTPs"
    - "Note in tipper 12345: skip this hunt"
    - After analyzing a tipper, if user wants findings added as a note

    This tool posts a comment to the specified tipper in Azure DevOps.
    Can be used standalone or chained after analyze_tipper_novelty.

    Args:
        tipper_id: The Azure DevOps work item ID for the tipper
        note: The note text to add as a comment

    Returns:
        Confirmation message with link to the tipper
    """
    try:
        from services.azdo import add_comment_to_work_item, fetch_work_items
        from my_config import get_config

        logger.info(f"Adding note to tipper #{tipper_id}...")

        config = get_config()

        # Validate work item exists before attempting to add comment
        validation_query = f"SELECT [System.Id] FROM WorkItems WHERE [System.Id] = {tipper_id}"
        existing_items = fetch_work_items(validation_query)

        if not existing_items:
            logger.warning(f"Work item #{tipper_id} not found in Azure DevOps")
            return f"⚠️ **Work item #{tipper_id} not found.** Please verify the tipper ID exists in Azure DevOps."

        # Convert work item references (#12345) to hyperlinks
        linked_note = _linkify_work_items(note, config.azdo_org, config.azdo_de_project)

        # Convert Markdown formatting to HTML (bold, line breaks)
        html_note = _markdown_to_html(linked_note)

        # Format note with header
        formatted_note = f"""<div>
<p><strong>🤖 Note from Pokedex:</strong></p>
<div>{html_note}</div>
</div>"""

        result = add_comment_to_work_item(int(tipper_id), formatted_note)

        if result:
            azdo_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_de_project}/_workitems/edit/{tipper_id}"
            return f"✅ **Note added to tipper #{tipper_id}**\n🔗 [View Tipper in AZDO]({azdo_url})"
        else:
            return f"⚠️ **Could not add note to tipper #{tipper_id}.** (Check AZDO connectivity)"

    except Exception as e:
        logger.error(f"Error adding note to tipper {tipper_id}: {e}", exc_info=True)
        return f"Error adding note: {str(e)}"


@readonly_tool
@log_tool_call
def analyze_threat_text(threat_description: str) -> str:
    """
    Analyze threat intelligence text for novelty without a tipper ID.

    USE THIS TOOL when users ask:
    - "Have we seen this threat before: [description]"
    - "Is this new: APT group using Cobalt Strike..."
    - "Check if we've encountered this technique"
    - "Analyze this threat: [paste threat intel]"

    This tool analyzes raw threat text against the historical tipper database
    to determine if similar threats have been seen before.

    Args:
        threat_description: The threat intelligence text to analyze

    Returns:
        Formatted analysis with novelty score and similar past tippers
    """
    try:
        from src.components.tipper_analyzer import TipperAnalyzer

        logger.info("Analyzing threat text for novelty...")

        analyzer = TipperAnalyzer()
        analysis = analyzer.analyze_tipper(tipper_text=threat_description)

        return FINAL_RESPONSE_PREFIX + analyzer.format_analysis_for_display(analysis)

    except RuntimeError as e:
        logger.error(f"Analysis failed: {e}")
        if "index" in str(e).lower():
            return FINAL_RESPONSE_PREFIX + (
                f"Error: Tipper similarity index not available. "
                f"The index may need to be built first. Please contact an admin."
            )
        return FINAL_RESPONSE_PREFIX + f"Error analyzing threat: {str(e)}"

    except Exception as e:
        logger.error(f"Error analyzing threat text: {e}", exc_info=True)
        return FINAL_RESPONSE_PREFIX + f"Error analyzing threat: {str(e)}"


# =============================================================================
# SAMPLE PROMPTS FOR LLM GUIDANCE
# =============================================================================
# Use these prompts to help users discover tipper analysis capabilities:
#
# - "Analyze tipper 12345 for novelty"
# - "Is tipper 67890 new or have we seen it before?"
# - "Check tipper 12345 against historical data"
# - "What's novel about tipper 99999?"
# - "Add note to tipper 12345: Known TTPs, skip this hunt"
# - "Have we seen this threat before: APT group using Cobalt Strike..."
# - "Check if we've encountered this technique: lateral movement via RDP"
# =============================================================================
