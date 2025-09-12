#!/usr/bin/env python3
"""
Manual Document Index Rebuild Script

Run this script when documents are not being found in search.
This will rebuild the entire vector store from scratch and automatically
restart the preloader service to load the updated documents.
"""

import subprocess
import platform
import sys
import os

# Add the parent directory to the path so we can import bot modules
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(script_dir))
sys.path.insert(0, project_root)

from my_bot.core.my_model import initialize_model_and_agent
from my_bot.core.state_manager import get_state_manager


def restart_preloader():
    """Restart the preloader service to load updated vector store"""
    try:
        if platform.system() == "Darwin":  # macOS
            print("🔄 Restarting macOS preloader service...")
            # Stop the service
            subprocess.run(["launchctl", "stop", "com.acme.soc-bot-preloader"],
                           check=False, capture_output=True)
            # Start the service
            subprocess.run(["launchctl", "start", "com.acme.soc-bot-preloader"],
                           check=True, capture_output=True, text=True)
            print("✅ Preloader service restarted successfully!")
            print("🔥 Updated documents are now available for search!")

        elif platform.system() == "Linux":  # Linux
            print("🔄 Restarting Linux preloader service...")
            subprocess.run(["sudo", "systemctl", "restart", "soc-bot-preloader"],
                           check=True, capture_output=True)
            print("✅ Preloader service restarted successfully!")
            print("🔥 Updated documents are now available for search!")

        else:
            print("⚠️  Manual restart needed: Preloader service restart not supported on this OS")
            print("   Please manually restart the preloader service to load updated documents.")

    except subprocess.CalledProcessError as e:
        print(f"⚠️  Could not restart preloader service: {e}")
        print("   You may need to manually restart it:")
        print("   macOS: launchctl stop/start com.acme.soc-bot-preloader")
        print("   Linux: sudo systemctl restart soc-bot-preloader")
    except Exception as e:
        print(f"⚠️  Error restarting preloader: {e}")


def main():
    print("🔄 Rebuilding document vector store...")
    print("=" * 50)

    # Initialize the system
    success = initialize_model_and_agent()

    if not success:
        print("❌ Failed to initialize system")
        return

    # Get components
    state_manager = get_state_manager()
    doc_processor = state_manager.get_document_processor()
    embeddings = state_manager.get_embeddings()

    if not doc_processor or not embeddings:
        print("❌ Required components not available")
        return

    # Force rebuild
    print("🔨 Force rebuilding vector store...")
    rebuild_success = doc_processor.force_rebuild(embeddings)

    if rebuild_success:
        print("✅ Document index rebuilt successfully!")
        print("\n📄 All PDFs, Word docs, and Excel files have been re-processed.")
        print("🔍 Missing documents should now be searchable.")

        # Automatically restart preloader service to load updated vector store
        print("\n🔄 Restarting preloader service to load updated documents...")
        restart_preloader()
    else:
        print("❌ Rebuild failed - check logs for errors")


if __name__ == "__main__":
    main()
