#!/usr/bin/env python3
"""
Helper script to add a new bot to the peer ping network.

This script helps you:
1. Choose where to insert the new bot in the ring
2. Updates my_config.py with new bot email field
3. Shows you what code to add to your new bot
4. Shows you what to change in the existing bot
"""

import sys
from pathlib import Path


def snake_to_pascal(name: str) -> str:
    """Convert snake_case to PascalCase"""
    return ''.join(word.capitalize() for word in name.split('_'))


def main():
    if len(sys.argv) < 2:
        print("Usage: python add_bot_to_peer_ping.py <new_bot_name>")
        print()
        print("Example:")
        print("  python add_bot_to_peer_ping.py skynet")
        print()
        sys.exit(1)

    new_bot_name = sys.argv[1].lower()
    new_bot_pascal = snake_to_pascal(new_bot_name)
    new_bot_env_var = f"WEBEX_BOT_EMAIL_{new_bot_name.upper()}"

    print(f"🤖 Adding '{new_bot_pascal}' to peer ping network")
    print("=" * 60)
    print()

    # Step 1: Show current topology
    print("📊 Current Topology:")
    print("   Toodles → Jarvis → Barnacles → Money_Ball → Toodles ⟲")
    print("   msoar → Toodles (spoke)")
    print()

    # Step 2: Ask where to insert
    print("❓ Where should we insert the new bot?")
    print()
    print("Options:")
    print("  1. Insert into main ring between Money_Ball and Toodles")
    print("     Result: ...Money_Ball → NewBot → Toodles...")
    print()
    print("  2. Insert into main ring between Toodles and Jarvis")
    print("     Result: ...Toodles → NewBot → Jarvis...")
    print()
    print("  3. Create spoke (point new bot at existing bot)")
    print("     Result: NewBot → Toodles (no changes to other bots)")
    print()

    choice = input("Choose option (1/2/3): ").strip()

    print()
    print("=" * 60)
    print("🔧 Implementation Steps")
    print("=" * 60)
    print()

    # Step 1: .env
    print("STEP 1: Add to .env file")
    print("-" * 60)
    print(f"{new_bot_env_var}={new_bot_name}@webex.bot")
    print()

    # Step 2: my_config.py
    print("STEP 2: Update my_config.py")
    print("-" * 60)
    print("Add to get_config() function:")
    print(f"    webex_bot_email_{new_bot_name}=os.environ.get(\"{new_bot_env_var}\"),")
    print()
    print("Add to Config dataclass:")
    print(f"    webex_bot_email_{new_bot_name}: Optional[str] = None")
    print()

    # Step 3: New bot configuration
    print(f"STEP 3: Configure {new_bot_pascal} bot")
    print("-" * 60)
    print(f"In webex_bots/{new_bot_name}.py, add to main():")
    print()
    print(f"    from src.utils.bot_resilience import ResilientBot")
    print(f"    config = get_config()")
    print()
    print(f"    resilient_runner = ResilientBot(")
    print(f"        bot_name=\"{new_bot_pascal}\",")
    print(f"        bot_factory={new_bot_name}_bot_factory,")
    print(f"        initialization_func=lambda bot: {new_bot_name}_initialization_with_tracking(bot, resilient_runner),")

    if choice == "1":
        target = "toodles"
        predecessor = "money_ball"
    elif choice == "2":
        target = "jarvis"
        predecessor = "toodles"
    else:
        target = "toodles"
        predecessor = None

    print(f"        peer_bot_email=config.webex_bot_email_{target},  # {new_bot_pascal} → {target.title()}")
    print(f"        peer_ping_interval_minutes=10,")
    print(f"    )")
    print(f"    resilient_runner.run()")
    print()

    # Step 4: Update existing bot (if inserting into ring)
    if predecessor:
        print(f"STEP 4: Update {predecessor}.py to point to new bot")
        print("-" * 60)
        print(f"In webex_bots/{predecessor}.py, change:")
        print()
        print(f"    # OLD:")
        print(f"    peer_bot_email=config.webex_bot_email_{target},  # {predecessor.title()} → {target.title()}")
        print()
        print(f"    # NEW:")
        print(f"    peer_bot_email=config.webex_bot_email_{new_bot_name},  # {predecessor.title()} → {new_bot_pascal}")
        print()

        print("RESULT:")
        print("-" * 60)
        if choice == "1":
            print("   ...Money_Ball → NewBot → Toodles...")
        else:
            print("   ...Toodles → NewBot → Jarvis...")
    else:
        print("STEP 4: No changes needed to other bots (spoke configuration)")
        print("-" * 60)
        print(f"   {new_bot_pascal} will ping Toodles, but no bot pings {new_bot_pascal}")

    print()
    print("=" * 60)
    print("✅ After making these changes:")
    print("   1. Copy .env to VM: scp .env lab-vm:~/pub/IR/")
    print("   2. Commit and push changes")
    print("   3. Run: restart_all_bots")
    print()
    print("Verify with: python show_peer_ping_topology.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
