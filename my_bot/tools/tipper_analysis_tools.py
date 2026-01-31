"""
Tipper Analysis Tools Module

Tools for analyzing threat tippers for novelty against historical data.
"""

import logging
import re
from typing import Any

from langchain_core.tools import tool

from my_config import get_config
from src.utils.tool_decorator import log_tool_call

logger = logging.getLogger(__name__)

CONFIG = get_config()

# Room ID for tipper analysis cards
TIPPER_ANALYSIS_ROOM_ID = CONFIG.webex_room_id_threat_tipper_analysis  # Production room


def build_write_note_card(tipper_id: str, tipper_title: str, html_comment: str) -> dict:
    """
    Build a simple adaptive card with just the "Write Note to AZDO" button.

    Args:
        tipper_id: The tipper work item ID
        tipper_title: The tipper title for display
        html_comment: Pre-formatted HTML comment to post to AZDO (included in card action data)

    Returns:
        dict: Adaptive card attachment ready to send via Webex
    """
    # Truncate title if needed
    title_display = tipper_title[:50]
    if len(tipper_title) > 50:
        title_display += "..."

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.3",
        "body": [
            {
                "type": "TextBlock",
                "text": f"Ready to write analysis for **Tipper #{tipper_id}**",
                "wrap": True
            }
        ],
        "actions": [
            {
                "type": "Action.Submit",
                "title": "📝 Write Note to AZDO",
                "style": "positive",
                "data": {
                    "callback_keyword": "write_tipper_note",
                    "tipper_id": tipper_id,
                    "html_comment": html_comment
                }
            }
        ]
    }

    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": card
    }


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


@tool
@log_tool_call
def analyze_tipper_novelty(tipper_id: str, post_to_azdo: bool = False) -> str:
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

    IMPORTANT: If the user asks to "notate", "add note", "post to AZDO", or
    "write findings to the tipper", set post_to_azdo=True to automatically
    post the full analysis as a comment on the work item.

    This tool:
    1. Fetches the tipper from Azure DevOps
    2. Searches for similar historical tippers using vector similarity
    3. Uses AI to analyze novelty and identify what's new vs familiar
    4. Returns a novelty score (1-10) and actionable recommendation
    5. Presents an adaptive card with a "Write Note" button to confirm before posting to AZDO
    6. If post_to_azdo=True, posts immediately without waiting for confirmation

    Args:
        tipper_id: The Azure DevOps work item ID for the tipper (e.g., "12345")
        post_to_azdo: If True, posts the full analysis as a comment on the tipper immediately

    Returns:
        Formatted analysis with novelty score, what's new, what's familiar,
        related tickets, and recommendation (PRIORITIZE/STANDARD/EXPEDITE)
    """
    try:
        from src.components.tipper_analyzer import TipperAnalyzer
        from my_config import get_config

        logger.info(f"Analyzing tipper #{tipper_id} for novelty...")

        analyzer = TipperAnalyzer()

        # If post_to_azdo=True, use the full flow (analyze + post + IOC hunt + post)
        if post_to_azdo:
            # Pass room_id so IOC hunt follow-up is sent to Webex
            result = analyzer.analyze_and_post(
                tipper_id, source="tool", room_id=TIPPER_ANALYSIS_ROOM_ID
            )
            config = get_config()
            azdo_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_de_project}/_workitems/edit/{tipper_id}"

            # Send analysis directly to Webex (tool sends it, LLM shouldn't duplicate)
            try:
                from webexpythonsdk import WebexAPI
                webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_pokedex)

                # Linkify work item references for Webex markdown
                webex_markdown = _linkify_work_items_markdown(
                    result['content'],
                    config.azdo_org,
                    config.azdo_de_project
                )
                webex_api.messages.create(
                    roomId=TIPPER_ANALYSIS_ROOM_ID,
                    markdown=webex_markdown
                )
                logger.info(f"Sent tipper analysis to Webex for #{tipper_id}")

                # Return minimal confirmation so LLM doesn't duplicate the output
                return f"✅ Analysis written to tipper #{tipper_id}\n🔗 [View Tipper in AZDO]({azdo_url})"

            except Exception as webex_error:
                logger.error(f"Failed to send to Webex: {webex_error}")
                # Fall back to returning content for LLM to send
                return result['content'] + f"\n\n🔗 [View Tipper]({azdo_url})"

        # Otherwise, just analyze without posting
        analysis = analyzer.analyze_tipper(tipper_id=tipper_id)
        display_output = analyzer.format_analysis_for_display(analysis)

        # Send analysis as markdown message, followed by a simple card with "Write Note" button
        try:
            from webexpythonsdk import WebexAPI

            webex_api = WebexAPI(access_token=CONFIG.webex_bot_access_token_pokedex)

            # 1. Linkify work item references for Webex markdown
            webex_markdown = _linkify_work_items_markdown(
                display_output,
                CONFIG.azdo_org,
                CONFIG.azdo_de_project
            )

            # 2. Send the analysis as a markdown message (much more readable)
            webex_api.messages.create(
                roomId=TIPPER_ANALYSIS_ROOM_ID,
                markdown=webex_markdown
            )
            logger.info(f"Sent tipper analysis markdown for #{tipper_id}")

            # 2. Pre-format the HTML comment for AZDO
            html_comment = analyzer.format_analysis_for_azdo(analysis)

            # 3. Send a simple card with just the "Write Note" button
            card_attachment = build_write_note_card(
                tipper_id=str(analysis.tipper_id),
                tipper_title=analysis.tipper_title,
                html_comment=html_comment
            )
            webex_api.messages.create(
                roomId=TIPPER_ANALYSIS_ROOM_ID,
                text=f"Write analysis to Tipper #{tipper_id}",
                attachments=[card_attachment]
            )
            logger.info(f"Sent write-note card for #{tipper_id}")

            # Analysis already sent to Webex - return minimal confirmation to avoid duplicate
            return f"✅ Analysis for tipper #{tipper_id} sent to the channel."

        except Exception as card_error:
            logger.error(f"Failed to send analysis to Webex: {card_error}")
            # Fall back to returning the full analysis for LLM to send
            return display_output

    except ValueError as e:
        logger.error(f"Tipper not found: {e}")
        return f"Error: Tipper #{tipper_id} not found in the Threat Hunting area. Please verify the tipper ID is correct and belongs to Threat Hunting."

    except RuntimeError as e:
        logger.error(f"Analysis failed: {e}")
        if "index" in str(e).lower():
            return (
                f"Error: Tipper similarity index not available. "
                f"The index may need to be built first. Please contact an admin."
            )
        return f"Error analyzing tipper: {str(e)}"

    except Exception as e:
        logger.error(f"Error analyzing tipper {tipper_id}: {e}", exc_info=True)
        return f"Error analyzing tipper: {str(e)}"


def write_analysis_to_azdo(tipper_id: str, html_comment: str) -> str:
    """
    Write a tipper analysis to AZDO.

    Called by the Webex callback handler when user clicks "Write Note" button.
    The HTML_comment is passed directly from the card's action data.

    Args:
        tipper_id: The tipper ID to write the analysis for
        html_comment: Pre-formatted HTML comment to post to AZDO

    Returns:
        str: Success/error message
    """
    try:
        from services.azdo import add_comment_to_work_item
        from my_config import get_config

        if not html_comment:
            logger.warning(f"No HTML comment provided for tipper #{tipper_id}")
            return f"⚠️ No analysis data found. Please run the analysis again."

        logger.info(f"Writing analysis to tipper #{tipper_id}...")

        # Post the HTML comment to AZDO
        result = add_comment_to_work_item(int(tipper_id), html_comment)

        if result:
            config = get_config()
            azdo_url = f"https://dev.azure.com/{config.azdo_org}/{config.azdo_de_project}/_workitems/edit/{tipper_id}"
            return f"✅ **Analysis written to tipper #{tipper_id}**\n🔗 [View Tipper in AZDO]({azdo_url})"
        else:
            return f"⚠️ Failed to write analysis to tipper #{tipper_id}. Check AZDO connectivity."

    except Exception as e:
        logger.error(f"Error writing analysis for tipper {tipper_id}: {e}", exc_info=True)
        return f"❌ Error writing analysis: {str(e)}"


@tool
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


@tool
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

        return analyzer.format_analysis_for_display(analysis)

    except RuntimeError as e:
        logger.error(f"Analysis failed: {e}")
        if "index" in str(e).lower():
            return (
                f"Error: Tipper similarity index not available. "
                f"The index may need to be built first. Please contact an admin."
            )
        return f"Error analyzing threat: {str(e)}"

    except Exception as e:
        logger.error(f"Error analyzing threat text: {e}", exc_info=True)
        return f"Error analyzing threat: {str(e)}"


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
# - "Analyze tipper 67890 and post to AZDO"
# - "Have we seen this threat before: APT group using Cobalt Strike..."
# - "Check if we've encountered this technique: lateral movement via RDP"
# =============================================================================
