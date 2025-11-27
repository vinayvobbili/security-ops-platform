#!/usr/bin/env python3
"""Test script to demonstrate XsoarConfig integration.

This script shows how changing XsoarConfig.MAX_WORKERS automatically
updates both the connection pool size and worker count used throughout the codebase.
"""

from src.config import XsoarConfig
from src.components.web.meaningful_metrics_handler import ExportConfig


def print_config():
    """Print current configuration."""
    print("=" * 70)
    print("Current XSOAR Configuration")
    print("=" * 70)
    print(f"XsoarConfig.MAX_WORKERS:              {XsoarConfig.MAX_WORKERS}")
    print(f"XsoarConfig.get_pool_size():          {XsoarConfig.get_pool_size()}")
    print(f"  (calculated as MAX_WORKERS + {XsoarConfig.POOL_SIZE_BUFFER} buffer)")
    print()
    print(f"ExportConfig.TIMEOUT_PER_TICKET:      {ExportConfig.TIMEOUT_PER_TICKET}s")
    print(f"ExportConfig.PROGRESS_LOG_INTERVAL:   {ExportConfig.PROGRESS_LOG_INTERVAL}")
    print()
    print("Note: All export functions now use XsoarConfig.MAX_WORKERS directly")
    print("=" * 70)
    print()


if __name__ == "__main__":
    print("\n✓ Default configuration (10 workers):")
    print_config()

    print("Changing XsoarConfig.MAX_WORKERS to 20...\n")
    XsoarConfig.MAX_WORKERS = 20

    print("✓ Updated configuration (20 workers):")
    print_config()

    print("✅ Summary:")
    print("  • Connection pool size automatically increased to 25 (20 + 5)")
    print("  • All export and enrichment operations will now use 20 workers")
    print("  • No need to update pool size separately - it's calculated automatically!")
    print()
    print("📝 To change worker count in your code:")
    print("   Just update: XsoarConfig.MAX_WORKERS = <your_value>")
    print("   Everything else adjusts automatically!")
