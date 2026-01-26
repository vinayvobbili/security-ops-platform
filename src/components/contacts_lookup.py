# /src/components/contacts_lookup.py
"""
Contacts Lookup with Vector Store + LLM

Provides intelligent contact search using:
1. A dedicated ChromaDB vector store for the contacts Excel file
2. LLM to format and respond to queries naturally
"""

import logging
import hashlib
from pathlib import Path
from typing import List, Optional

import chromadb
import pandas as pd
import requests

logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
CONTACTS_FILE = PROJECT_ROOT / "local_pdfs_docs" / "Updated_Escalations Paths Global JV Contact listing.xlsx"
CONTACTS_CHROMA_PATH = PROJECT_ROOT / "data" / "chroma_contacts"


class ContactsVectorStore:
    """Manages a dedicated vector store for contacts lookup."""

    def __init__(self):
        self.chroma_client = None
        self.collection = None
        self._initialized = False
        self._embedding_batch_size = 50  # Max texts per API call

    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding from Ollama for a single text."""
        try:
            response = requests.post(
                "http://localhost:11434/api/embed",
                json={"model": "nomic-embed-text", "input": text},
                timeout=30
            )
            response.raise_for_status()
            return response.json()["embeddings"][0]
        except Exception as e:
            logger.error(f"Embedding error: {e}")
            raise

    def _get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """Get embeddings from Ollama for a batch of texts in a single API call."""
        if not texts:
            return []

        try:
            response = requests.post(
                "http://localhost:11434/api/embed",
                json={"model": "nomic-embed-text", "input": texts},
                timeout=120  # Longer timeout for batches
            )
            response.raise_for_status()
            return response.json()["embeddings"]
        except Exception as e:
            logger.error(f"Batch embedding error: {e}")
            raise

    def initialize(self) -> bool:
        """Initialize or load the contacts vector store."""
        try:
            CONTACTS_CHROMA_PATH.mkdir(parents=True, exist_ok=True)

            self.chroma_client = chromadb.PersistentClient(path=str(CONTACTS_CHROMA_PATH))
            self.collection = self.chroma_client.get_or_create_collection(
                name="contacts",
                metadata={"description": "Escalation contacts"}
            )

            # Check if we need to build the index
            if self.collection.count() == 0:
                logger.info("Building contacts vector store...")
                self._build_index()

            self._initialized = True
            logger.info(f"Contacts vector store ready with {self.collection.count()} entries")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize contacts vector store: {e}")
            return False

    def _build_index(self):
        """Build the vector store from the contacts Excel file."""
        if not CONTACTS_FILE.exists():
            raise FileNotFoundError(f"Contacts file not found: {CONTACTS_FILE}")

        xl = pd.ExcelFile(CONTACTS_FILE)
        documents = []
        ids = []
        embeddings = []
        doc_counter = 0

        for sheet_name in xl.sheet_names:
            df = pd.read_excel(CONTACTS_FILE, sheet_name=sheet_name)

            # Track the last group name (first column) for continuation rows
            last_group_name = ""

            for idx, row in df.iterrows():
                # Build a text representation of the row
                parts = []
                first_col_value = ""

                for col_idx, val in enumerate(row.values):
                    if pd.notna(val):
                        val_str = str(val).strip()
                        if val_str:
                            parts.append(val_str)
                            if col_idx == 0:
                                first_col_value = val_str

                # Update group name if first column has a value
                if first_col_value:
                    last_group_name = first_col_value
                elif last_group_name and parts:
                    # Continuation row - prepend the group name
                    parts.insert(0, f"({last_group_name})")

                if parts:
                    # Create document text with sheet context
                    doc_text = f"Region/Sheet: {sheet_name}. Contact: {' | '.join(parts)}"
                    # Use counter for unique IDs
                    doc_id = f"contact_{doc_counter}"
                    doc_counter += 1

                    documents.append(doc_text)
                    ids.append(doc_id)

        # Generate embeddings in batches (much faster than one-by-one)
        logger.info(f"Generating embeddings for {len(documents)} contact entries in batches...")

        # Process in batches for efficiency
        for i in range(0, len(documents), self._embedding_batch_size):
            batch = documents[i:i + self._embedding_batch_size]
            batch_embeddings = self._get_embeddings_batch(batch)
            embeddings.extend(batch_embeddings)

            if len(documents) > self._embedding_batch_size:
                logger.info(f"  Processed {min(i + self._embedding_batch_size, len(documents))}/{len(documents)} embeddings...")

        # Add to collection
        self.collection.add(
            documents=documents,
            ids=ids,
            embeddings=embeddings
        )
        logger.info(f"Added {len(documents)} contacts to vector store")

    def search(self, query: str, n_results: int = 10) -> List[str]:
        """Search for contacts matching the query using hybrid approach."""
        if not self._initialized:
            self.initialize()

        try:
            # First, try keyword matching (more reliable for exact terms)
            all_docs = self.collection.get()
            keyword_matches = []
            query_lower = query.lower()

            for doc in all_docs['documents']:
                if query_lower in doc.lower():
                    keyword_matches.append(doc)

            # If we have keyword matches, return those
            if keyword_matches:
                return keyword_matches[:n_results]

            # Otherwise, fall back to vector search
            query_embedding = self._get_embedding(query)
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=n_results
            )
            return results['documents'][0] if results['documents'] else []
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []

    def rebuild(self):
        """Force rebuild the vector store."""
        if self.collection:
            # Delete all entries
            ids = self.collection.get()['ids']
            if ids:
                self.collection.delete(ids=ids)
        self._build_index()


# Singleton instance
_contacts_store: Optional[ContactsVectorStore] = None


def get_contacts_store() -> ContactsVectorStore:
    """Get or create the contacts vector store singleton."""
    global _contacts_store
    if _contacts_store is None:
        _contacts_store = ContactsVectorStore()
        _contacts_store.initialize()
    return _contacts_store


def search_contacts_with_llm_with_metrics(query: str) -> dict:
    """
    Search contacts and use LLM to format the response, returning token metrics.

    Args:
        query: The search query (e.g., "major incident management", "EMEA")

    Returns:
        dict with 'content' and token metrics
    """
    # Default metrics for error/fallback cases
    default_metrics = {
        'content': '',
        'input_tokens': 0,
        'output_tokens': 0,
        'total_tokens': 0,
        'prompt_time': 0.0,
        'generation_time': 0.0,
        'tokens_per_sec': 0.0
    }

    try:
        # Get relevant contacts from vector store
        store = get_contacts_store()
        contacts = store.search(query, n_results=10)

        if not contacts:
            default_metrics['content'] = f"❌ No contacts found for '{query}'."
            return default_metrics

        # Build context for LLM
        context = "Here are the relevant contacts from the escalation paths document:\n\n"
        for i, contact in enumerate(contacts, 1):
            context += f"{i}. {contact}\n"

        # Query LLM with context
        prompt = f"""{context}

Based on the contacts above, answer this query: "{query}"

Format each contact like this (make the values bold, not the labels):
- Name: **[Full Name]**
  Email: [email@domain.com]

Include phone number only if available. Be concise."""

        # Call Ollama directly for speed
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "qwen2.5:32b",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1}
            },
            timeout=60
        )
        response.raise_for_status()
        result = response.json()

        # Extract token metrics from Ollama response
        input_tokens = result.get('prompt_eval_count', 0)
        output_tokens = result.get('eval_count', 0)
        prompt_time = result.get('prompt_eval_duration', 0) / 1e9  # ns to seconds
        generation_time = result.get('eval_duration', 0) / 1e9  # ns to seconds
        tokens_per_sec = output_tokens / generation_time if generation_time > 0 else 0.0

        llm_response = result.get('response', '').strip()
        if llm_response:
            content = f"📇 Contacts for '**{query}**'\n\n{llm_response}"
        else:
            # Fallback to raw results
            content = f"📇 Contacts for '**{query}**'\n\n"
            for contact in contacts[:10]:
                content += f"- {contact}\n"

        return {
            'content': content,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
            'total_tokens': input_tokens + output_tokens,
            'prompt_time': prompt_time,
            'generation_time': generation_time,
            'tokens_per_sec': tokens_per_sec
        }

    except Exception as e:
        logger.error(f"Contacts lookup error: {e}", exc_info=True)
        default_metrics['content'] = f"❌ Error looking up contacts: {str(e)}"
        return default_metrics


def search_contacts_with_llm(query: str) -> str:
    """
    Search contacts and use LLM to format the response.

    Args:
        query: The search query (e.g., "major incident management", "EMEA")

    Returns:
        Formatted response from LLM
    """
    result = search_contacts_with_llm_with_metrics(query)
    return result['content']


if __name__ == "__main__":
    # Test the contacts lookup
    logging.basicConfig(level=logging.INFO)

    print("Testing contacts vector store...")
    result = search_contacts_with_llm("major incident management")
    print(result)
    print("\n" + "=" * 50 + "\n")
    result = search_contacts_with_llm("EMEA")
    print(result)
