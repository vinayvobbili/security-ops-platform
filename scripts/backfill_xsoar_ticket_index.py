#!/usr/bin/env python3
"""
Backfill script to populate/rebuild the XSOAR ticket ChromaDB similarity index.

Indexes closed XSOAR tickets for semantic similarity search used by the
triage pipeline to predict impact on new tickets.

Usage:
    python scripts/backfill_xsoar_ticket_index.py rebuild
    python scripts/backfill_xsoar_ticket_index.py rebuild --days-back 730
    python scripts/backfill_xsoar_ticket_index.py sync
    python scripts/backfill_xsoar_ticket_index.py stats
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def main():
    parser = argparse.ArgumentParser(description="Manage XSOAR ticket similarity index")
    parser.add_argument(
        "command",
        choices=["sync", "rebuild", "stats"],
        help="sync=incremental upsert, rebuild=full rebuild, stats=show index info",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=365,
        help="Number of days of history to fetch (default: 365)",
    )
    args = parser.parse_args()

    from src.components.xsoar_ticket_indexer import (
        sync_xsoar_ticket_index,
        rebuild_xsoar_ticket_index,
        show_stats,
    )

    if args.command == "sync":
        sync_xsoar_ticket_index(days_back=args.days_back)
    elif args.command == "rebuild":
        rebuild_xsoar_ticket_index(days_back=args.days_back)
    elif args.command == "stats":
        show_stats()


if __name__ == "__main__":
    main()
