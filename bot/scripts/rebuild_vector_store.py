#!/usr/bin/env python3
"""
Manual Document Index Rebuild Script

Run this script in PyCharm when documents are not being found in search.
This will rebuild the entire vector store from scratch.
"""

from bot.core.my_model import initialize_model_and_agent
from bot.core.state_manager import get_state_manager

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
    else:
        print("❌ Rebuild failed - check logs for errors")

if __name__ == "__main__":
    main()