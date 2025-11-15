#!/usr/bin/env python3
"""
Visualize the current peer ping topology across all Webex bots.

Shows which bots are pinging which other bots, and identifies:
- Main ring (circular chain of bots)
- Spokes (bots pointing into the ring but not part of it)
- Orphans (bots with no peer ping configured)
"""

import re
from pathlib import Path
from typing import Dict, List, Set, Tuple


def extract_peer_ping_config(bot_file: Path) -> Tuple[str, str]:
    """
    Extract peer ping configuration from a bot file.

    Returns:
        (bot_name, target_bot_email) or (bot_name, None) if no peer ping configured
    """
    content = bot_file.read_text()

    # Extract bot name from ResilientBot configuration
    bot_name_match = re.search(r'bot_name\s*=\s*["\']([^"\']+)["\']', content)
    bot_name = bot_name_match.group(1) if bot_name_match else bot_file.stem

    # Extract peer_bot_email configuration
    peer_email_match = re.search(r'peer_bot_email\s*=\s*config\.webex_bot_email_(\w+)', content)
    target = peer_email_match.group(1) if peer_email_match else None

    return bot_name, target


def find_cycles(graph: Dict[str, str]) -> List[List[str]]:
    """Find all cycles in the peer ping graph."""
    cycles = []
    visited = set()

    for start_node in graph:
        if start_node in visited:
            continue

        path = []
        current = start_node
        path_set = set()

        while current and current not in visited:
            if current in path_set:
                # Found a cycle
                cycle_start = path.index(current)
                cycle = path[cycle_start:]
                cycles.append(cycle)
                visited.update(cycle)
                break

            path.append(current)
            path_set.add(current)
            current = graph.get(current)
        else:
            # Reached end without cycle
            visited.update(path)

    return cycles


def main():
    """Analyze and display peer ping topology."""
    webex_bots_dir = Path(__file__).parent / 'webex_bots'

    if not webex_bots_dir.exists():
        print("❌ webex_bots directory not found")
        return

    # Build the peer ping graph
    graph: Dict[str, str] = {}  # bot_name -> target_bot_name
    bot_files = {}  # bot_name -> file_path
    name_mapping = {}  # normalized_name -> display_name

    for bot_file in webex_bots_dir.glob('*.py'):
        if bot_file.name.startswith('_'):
            continue

        bot_name, target = extract_peer_ping_config(bot_file)
        normalized_name = bot_name.lower().replace(' ', '').replace('_', '')
        bot_files[normalized_name] = bot_file
        name_mapping[normalized_name] = bot_name

        if target:
            normalized_target = target.lower().replace(' ', '').replace('_', '')
            graph[normalized_name] = normalized_target

    print("🌐 Webex Bot Peer Ping Topology")
    print("=" * 60)
    print()

    # Find cycles (rings)
    cycles = find_cycles(graph)

    if cycles:
        print("🔄 Main Ring(s):")
        for i, cycle in enumerate(cycles, 1):
            display_cycle = [name_mapping.get(bot, bot) for bot in cycle]
            print(f"   Ring {i}: {' → '.join(display_cycle)} → {display_cycle[0]} ⟲")
        print()

    # Find spokes (bots pointing into ring but not in it)
    ring_bots = set()
    for cycle in cycles:
        ring_bots.update(cycle)

    spokes = {bot: target for bot, target in graph.items() if bot not in ring_bots}

    if spokes:
        print("📍 Spokes (pointing into ring):")
        for bot, target in spokes.items():
            bot_display = name_mapping.get(bot, bot)
            target_display = name_mapping.get(target, target)
            print(f"   {bot_display} → {target_display}")
        print()

    # Find orphans (no peer ping configured)
    all_bots = set(bot_files.keys())
    configured_bots = set(graph.keys())
    orphans = all_bots - configured_bots

    if orphans:
        print("⚠️  Orphans (no peer ping configured):")
        for bot in sorted(orphans):
            bot_display = name_mapping.get(bot, bot)
            print(f"   {bot_display}")
        print()

    # Summary
    print("📊 Summary:")
    print(f"   Total bots: {len(all_bots)}")
    print(f"   In main ring: {len(ring_bots)}")
    print(f"   Spokes: {len(spokes)}")
    print(f"   Orphans: {len(orphans)}")
    print()

    # Full graph visualization
    print("📋 Complete Peer Ping Map:")
    for bot in sorted(graph.keys(), key=lambda b: name_mapping.get(b, b).lower()):
        target = graph[bot]
        bot_display = name_mapping.get(bot, bot)
        target_display = name_mapping.get(target, target)
        status = "🔄" if bot in ring_bots else "📍"
        print(f"   {status} {bot_display:15} → {target_display}")

    if orphans:
        print()
        for bot in sorted(orphans, key=lambda b: name_mapping.get(b, b).lower()):
            bot_display = name_mapping.get(bot, bot)
            print(f"   ⚠️  {bot_display:15} → (none)")


if __name__ == "__main__":
    main()
