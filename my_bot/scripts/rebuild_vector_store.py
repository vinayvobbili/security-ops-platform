#!/usr/bin/env python3
"""
Manual Document Index Rebuild Script

Run this script when documents are not being found in search.
This will rebuild the ChromaDB collection from scratch and automatically
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

from my_bot.document.document_processor import DocumentProcessor


def restart_preloader():
    """Restart the preloader service to load updated vector store"""
    try:
        if platform.system() == "Darwin":  # macOS
            print("Restarting macOS preloader service...")
            subprocess.run(["launchctl", "stop", "com.company.soc-bot-preloader"],
                           check=False, capture_output=True)
            subprocess.run(["launchctl", "start", "com.company.soc-bot-preloader"],
                           check=True, capture_output=True, text=True)
            print("Preloader service restarted successfully!")

        elif platform.system() == "Linux":  # Linux
            print("Restarting Linux preloader service...")
            subprocess.run(["sudo", "systemctl", "restart", "soc-bot-preloader"],
                           check=True, capture_output=True)
            print("Preloader service restarted successfully!")

        else:
            print("Manual restart needed: Preloader service restart not supported on this OS")
            print("Please manually restart the preloader service to load updated documents.")

    except subprocess.CalledProcessError as e:
        print(f"Could not restart preloader service: {e}")
        print("You may need to manually restart it:")
        print("macOS: launchctl stop/start com.company.soc-bot-preloader")
        print("Linux: sudo systemctl restart soc-bot-preloader")
    except Exception as e:
        print(f"Error restarting preloader: {e}")


def main():
    print("Rebuilding document vector store (ChromaDB)...")
    print("=" * 50)

    # Setup paths
    pdf_directory_path = os.path.join(project_root, "local_pdfs_docs")
    chroma_path = os.path.join(project_root, "chroma_documents")

    # Check if documents directory exists
    if not os.path.exists(pdf_directory_path):
        print(f"Documents directory not found: {pdf_directory_path}")
        return

    # Initialize document processor
    print("Initializing document processor...")
    try:
        doc_processor = DocumentProcessor(
            pdf_directory=pdf_directory_path,
            chroma_path=chroma_path
        )
        print("Document processor initialized")
    except Exception as e:
        print(f"Failed to initialize document processor: {e}")
        return

    # Rebuild index from scratch
    print("Rebuilding ChromaDB collection from scratch...")
    rebuild_success = doc_processor.rebuild_index()

    if rebuild_success:
        print("Document index rebuilt successfully!")
        print("\nAll PDFs, Word docs, and Excel files have been re-processed.")
        print("Missing documents should now be searchable.")

        # Show stats
        stats = doc_processor.get_document_stats()
        print(f"\nIndex stats:")
        print(f"  - Total chunks: {stats.get('total_chunks', 'N/A')}")
        print(f"  - Storage path: {stats.get('chroma_path', 'N/A')}")

        # Automatically restart preloader service to load updated vector store
        print("\nRestarting preloader service to load updated documents...")
        restart_preloader()
    else:
        print("Rebuild failed - check logs for errors")


if __name__ == "__main__":
    main()
