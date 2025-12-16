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

from langchain_ollama import OllamaEmbeddings
from my_bot.document.document_processor import DocumentProcessor
from my_bot.utils.enhanced_config import ModelConfig


def restart_preloader():
    """Restart the preloader service to load updated vector store"""
    try:
        if platform.system() == "Darwin":  # macOS
            print("🔄 Restarting macOS preloader service...")
            # Stop the service
            subprocess.run(["launchctl", "stop", "com.company.soc-bot-preloader"],
                           check=False, capture_output=True)
            # Start the service
            subprocess.run(["launchctl", "start", "com.company.soc-bot-preloader"],
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
        print("   macOS: launchctl stop/start com.company.soc-bot-preloader")
        print("   Linux: sudo systemctl restart soc-bot-preloader")
    except Exception as e:
        print(f"⚠️  Error restarting preloader: {e}")


def main():
    print("🔄 Rebuilding document vector store...")
    print("=" * 50)

    # Setup paths
    pdf_directory_path = os.path.join(project_root, "local_pdfs_docs")
    faiss_index_path = os.path.join(project_root, "faiss_index_ollama")

    # Initialize embeddings
    print("🤖 Initializing embeddings model...")
    try:
        model_config = ModelConfig()
        embeddings = OllamaEmbeddings(
            model=model_config.embedding_model_name
        )
        print("✅ Embeddings initialized")
    except Exception as e:
        print(f"❌ Failed to initialize embeddings: {e}")
        return

    # Initialize document processor
    print("📄 Initializing document processor...")
    try:
        doc_processor = DocumentProcessor(
            pdf_directory=pdf_directory_path,
            faiss_index_path=faiss_index_path
        )
        print("✅ Document processor initialized")
    except Exception as e:
        print(f"❌ Failed to initialize document processor: {e}")
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
