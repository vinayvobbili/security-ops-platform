"""CLI entry points for tipper analysis.

Usage:
    # Analyze a tipper by ID
    python -m src.components.tipper_analyzer 12345

    # Analyze raw threat text
    python -m src.components.tipper_analyzer --text "APT group using Cobalt Strike..."
"""

import logging
from datetime import datetime, timedelta, timezone

import services.azdo as azdo
from my_config import get_config

from .analyzer import TipperAnalyzer
from .utils import linkify_work_items_markdown

logger = logging.getLogger(__name__)

# Load config for default room_id in analyze_recent_tippers
_config = get_config()


def analyze_from_cli(tipper_id: str = None, text: str = None):
    """CLI entry point for analysis."""
    print("\n🔍 Tipper Novelty Analyzer\n")

    # Initialize LLM
    print("Initializing LLM...")
    from my_bot.core.state_manager import get_state_manager
    state_manager = get_state_manager()

    if not state_manager.is_initialized:
        print("State manager not initialized. Initializing now...")
        state_manager.initialize_all_components()

    analyzer = TipperAnalyzer()

    if tipper_id:
        print(f"Analyzing tipper #{tipper_id}...\n")
        analysis = analyzer.analyze_tipper(tipper_id=tipper_id)
    elif text:
        print(f"Analyzing threat text...\n")
        analysis = analyzer.analyze_tipper(tipper_text=text)
    else:
        print("Error: Must provide --id or --text")
        return

    print(analyzer.format_analysis_for_display(analysis))
    return analysis


def analyze_recent_tippers(hours_back: int = 1, room_id: str = _config.webex_room_id_vinay_test_space) -> int:
    """
    Fetch and analyze tippers created in the last N hours.

    Sends analysis results to Webex for threat hunter review.
    Called by the hourly scheduled job in home_jobs.py.

    Args:
        hours_back: How many hours back to look for new tippers (default 1)
        room_id: Webex room ID to send results to (defaults to test space for safety)

    Returns:
        Number of tippers analyzed
    """
    from data.data_maps import azdo_area_paths
    from webexpythonsdk import WebexAPI
    from src.components.tipper_indexer import sync_tipper_index

    config = get_config()
    area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')

    # Sync any new tippers to ChromaDB (incremental - only adds missing ones)
    logger.info("Syncing new tippers to index...")
    try:
        sync_tipper_index(days_back=30)  # Only check recent tippers for efficiency
    except Exception as e:
        logger.warning(f"Tipper sync failed, continuing with existing index: {e}")

    # Calculate cutoff timestamp for Python filtering
    # Note: AZDO CreatedDate field has date-only precision in WIQL, so we fetch by date
    # and filter by actual timestamp in Python
    cutoff_utc = datetime.now(timezone.utc) - timedelta(hours=hours_back)

    # Query tippers from yesterday and today (to handle midnight boundary)
    # WIQL only supports date precision for CreatedDate comparisons
    query = f"""
        SELECT [System.Id], [System.Title], [System.Description],
               [System.CreatedDate], [System.Tags], [System.State]
        FROM WorkItems
        WHERE [System.AreaPath] UNDER '{area_path}'
          AND [System.CreatedDate] >= @Today-1
        ORDER BY [System.CreatedDate] DESC
    """

    logger.info(f"Fetching tippers from last {hours_back} hour(s) (cutoff: {cutoff_utc.isoformat()})...")
    all_tippers = azdo.fetch_work_items(query)

    if not all_tippers:
        logger.info("No tippers found from today/yesterday")
        return 0

    # Filter to tippers created after the cutoff time
    tippers = []
    for tipper in all_tippers:
        created_str = tipper.get('fields', {}).get('System.CreatedDate', '')
        if created_str:
            try:
                # Parse ISO format (AZDO returns UTC timestamps with full precision)
                created_dt = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
                if created_dt >= cutoff_utc:
                    tippers.append(tipper)
            except (ValueError, TypeError):
                continue

    if not tippers:
        logger.info(f"No new tippers in the last {hours_back} hour(s) (checked {len(all_tippers)} from today/yesterday)")
        print(f"  → No new tippers found (checked {len(all_tippers)} from today/yesterday)")
        return 0

    logger.info(f"Found {len(tippers)} tipper(s) to analyze (from {len(all_tippers)} today/yesterday)")
    tipper_ids = [str(t.get('id')) for t in tippers]
    print(f"  → Found {len(tippers)} new tipper(s): {', '.join(f'#{tid}' for tid in tipper_ids)}")

    # Initialize state manager for LLM
    from my_bot.core.state_manager import get_state_manager
    state_manager = get_state_manager()
    if not state_manager.is_initialized:
        logger.info("Initializing state manager for LLM...")
        state_manager.initialize_all_components()

    # Initialize analyzer and Webex API
    analyzer = TipperAnalyzer()
    webex_api = WebexAPI(access_token=config.webex_bot_access_token_pokedex)

    if not room_id:
        logger.error("No Webex room_id configured for tipper analysis")
        return 0

    analyzed_count = 0
    analyzed_ids = []
    for tipper in tippers:
        tipper_id = str(tipper.get('id'))
        title = tipper.get('fields', {}).get('System.Title', 'No title')

        try:
            logger.info(f"Analyzing tipper #{tipper_id}: {title[:50]}...")

            # Run full flow: analyze + post to AZDO + background IOC hunt
            result = analyzer.analyze_and_post(tipper_id, source="hourly", room_id=room_id)

            # Linkify work item references for Webex markdown
            webex_markdown = linkify_work_items_markdown(result['content'])

            # Send brief summary to Webex
            webex_api.messages.create(
                roomId=room_id,
                markdown=webex_markdown
            )
            logger.info(f"Sent analysis for tipper #{tipper_id} to Webex")

            analyzed_count += 1
            analyzed_ids.append(tipper_id)

        except Exception as e:
            logger.error(f"Failed to analyze tipper #{tipper_id}: {e}", exc_info=True)
            continue

    logger.info(f"Hourly analysis complete: {analyzed_count}/{len(tippers)} tippers analyzed")
    if analyzed_ids:
        print(f"  → Analyzed {analyzed_count}/{len(tippers)} tippers: {', '.join(f'#{tid}' for tid in analyzed_ids)}")
    else:
        print(f"  → Analyzed 0/{len(tippers)} tippers (all failed)")
    return analyzed_count


def handle_rules_cli(args: list):
    """Handle the 'rules' subcommand for detection rules catalog.

    Args:
        args: Remaining CLI arguments after 'rules'
    """
    from .rules import search_rules, sync_catalog, get_catalog_stats
    from .rules.formatters import format_rules_for_display, format_sync_result, format_catalog_stats

    # Parse rules subcommand args
    if not args or "--help" in args:
        print("Usage:")
        print("  python -m src.components.tipper_analyzer rules --search \"emotet\"")
        print("  python -m src.components.tipper_analyzer rules --search \"cobalt strike\" --platform crowdstrike")
        print("  python -m src.components.tipper_analyzer rules --sync [--full]")
        print("  python -m src.components.tipper_analyzer rules --stats")
        return

    if "--sync" in args:
        full_rebuild = "--full" in args
        platform_filter = None
        if "--platform" in args:
            idx = args.index("--platform")
            if idx + 1 < len(args):
                platform_filter = [args[idx + 1]]
        print("Syncing detection rules catalog...")
        result = sync_catalog(platforms=platform_filter, full_rebuild=full_rebuild)
        print(format_sync_result(result))

    elif "--stats" in args:
        stats = get_catalog_stats()
        print(format_catalog_stats(stats))

    elif "--search" in args:
        idx = args.index("--search")
        # Collect search terms (everything after --search until next flag)
        search_terms = []
        for i in range(idx + 1, len(args)):
            if args[i].startswith("--"):
                break
            search_terms.append(args[i])
        query = " ".join(search_terms)

        if not query:
            print("Error: --search requires a query string")
            return

        platform = None
        if "--platform" in args:
            p_idx = args.index("--platform")
            if p_idx + 1 < len(args):
                platform = args[p_idx + 1]

        k = 10
        if "--limit" in args:
            k_idx = args.index("--limit")
            if k_idx + 1 < len(args):
                try:
                    k = int(args[k_idx + 1])
                except ValueError:
                    pass

        result = search_rules(query, k=k, platform=platform)
        print(format_rules_for_display(result))
    else:
        print("Error: Unknown rules subcommand. Use --search, --sync, or --stats")


def main():
    """Main entry point for CLI."""
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m src.components.tipper_analyzer <tipper_id>")
        print("  python -m src.components.tipper_analyzer --text \"threat description...\"")
        print("  python -m src.components.tipper_analyzer rules --search|--sync|--stats")
        sys.exit(1)

    if sys.argv[1] == "rules":
        handle_rules_cli(sys.argv[2:])
    elif sys.argv[1] == "--text":
        text = " ".join(sys.argv[2:])
        analyze_from_cli(text=text)
    else:
        analyze_from_cli(tipper_id=sys.argv[1])
