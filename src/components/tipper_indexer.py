"""
Tipper Similarity Indexer

Indexes historical threat tippers from AZDO into ChromaDB for
similarity search when analyzing new tippers.

Uses ChromaDB with automatic persistence - no manual rebuilds needed.
New tippers are upserted incrementally.

Usage:
    # Sync new tippers (adds only missing ones)
    python -m src.components.tipper_indexer

    # Full rebuild (deletes and recreates collection)
    python -m src.components.tipper_indexer rebuild

    # Search for similar tippers
    python -m src.components.tipper_indexer search "APT group using Cobalt Strike"
"""

import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

import chromadb
import requests

import services.azdo as azdo
from data.data_maps import azdo_area_paths

logger = logging.getLogger(__name__)

# Paths
ROOT_DIRECTORY = Path(__file__).parent.parent.parent
CHROMA_PATH = ROOT_DIRECTORY / "data" / "transient" / "chroma_tipper_index"

# Collection name
COLLECTION_NAME = "threat_tippers"


class OllamaEmbeddingFunction:
    """Custom embedding function using Ollama API."""

    def __init__(self, model: str = None):
        # Use config if no model specified
        if model is None:
            from my_config import get_config
            config = get_config()
            model = config.ollama_embedding_model or "all-minilm:l6-v2"
        self.model = model
        self.api_url = "http://localhost:11434/api/embeddings"

    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts."""
        embeddings = []
        for text in input:
            embedding = self._embed_single(text)
            embeddings.append(embedding)
        return embeddings

    def _embed_single(self, text: str, max_retries: int = 3) -> List[float]:
        """Generate embedding for a single text."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json={"model": self.model, "prompt": text},
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                return result["embedding"]
            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Failed to embed text: {e}")


class TipperIndexer:
    """Handles indexing and similarity search for threat tippers using ChromaDB."""

    def __init__(self):
        self.chroma_path = str(CHROMA_PATH)
        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = OllamaEmbeddingFunction()

    @property
    def client(self) -> chromadb.PersistentClient:
        """Lazy-load ChromaDB client."""
        if self._client is None:
            self._client = chromadb.PersistentClient(path=self.chroma_path)
        return self._client

    @property
    def collection(self):
        """Get or create the tippers collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=COLLECTION_NAME,
                metadata={"description": "Threat tipper embeddings for similarity search"}
            )
        return self._collection

    # -------------------------------------------------------------------------
    # Fetch tippers from AZDO
    # -------------------------------------------------------------------------
    def fetch_historical_tippers(self, days_back: int = 365) -> List[dict]:
        """
        Fetch ALL tippers from AZDO for the specified time period.

        Args:
            days_back: How far back to fetch (default 1 year)

        Returns:
            List of tipper work items from AZDO
        """
        area_path = azdo_area_paths.get('threat_hunting', 'Detection-Engineering\\DE Rules\\Threat Hunting')

        query = f"""
            SELECT [System.Id], [System.Title], [System.Description],
                   [System.CreatedDate], [System.Tags], [System.State],
                   [Microsoft.VSTS.Common.ClosedDate]
            FROM WorkItems
            WHERE [System.AreaPath] UNDER '{area_path}'
              AND [System.CreatedDate] >= @Today-{days_back}
            ORDER BY [System.CreatedDate] DESC
        """

        logger.info(f"Fetching tippers from last {days_back} days...")
        work_items = azdo.fetch_work_items(query)

        if not work_items:
            logger.warning("No tippers found matching query")
            return []

        logger.info(f"Fetched {len(work_items)} tippers from AZDO")
        return work_items

    # -------------------------------------------------------------------------
    # Extract text for embedding
    # -------------------------------------------------------------------------
    def extract_tipper_text(self, tipper: dict) -> str:
        """Extract meaningful text from a tipper for embedding."""
        fields = tipper.get('fields', {})

        title = fields.get('System.Title', '')
        description = fields.get('System.Description', '')
        tags = fields.get('System.Tags', '')

        # Clean HTML from description
        if description:
            description = re.sub(r'<[^>]+>', ' ', description)
            description = re.sub(r'\s+', ' ', description).strip()

        # Combine into single text block
        text_parts = [
            f"Title: {title}",
            f"Tags: {tags}" if tags else "",
            f"Description: {description[:2000]}" if description else ""
        ]

        return "\n".join(part for part in text_parts if part)

    def prepare_tipper_metadata(self, tipper: dict) -> dict:
        """Extract metadata to store alongside the embedding."""
        fields = tipper.get('fields', {})

        return {
            'id': str(tipper.get('id', '')),
            'title': fields.get('System.Title', ''),
            'created_date': fields.get('System.CreatedDate', ''),
            'closed_date': fields.get('Microsoft.VSTS.Common.ClosedDate', '') or '',
            'state': fields.get('System.State', ''),
            'tags': fields.get('System.Tags', '') or '',
            'url': tipper.get('url', '') or '',
        }

    # -------------------------------------------------------------------------
    # Sync tippers (upsert new ones only)
    # -------------------------------------------------------------------------
    def sync_tippers(self, days_back: int = 365) -> int:
        """
        Sync tippers from AZDO to ChromaDB.

        Only upserts tippers that are new or updated. Much faster than
        a full rebuild since we skip existing tippers.

        Args:
            days_back: How far back to fetch from AZDO

        Returns:
            Number of tippers added/updated
        """
        logger.info("=" * 60)
        logger.info("TIPPER SYNC STARTING")
        logger.info("=" * 60)

        # Fetch tippers from AZDO
        tippers = self.fetch_historical_tippers(days_back)
        if not tippers:
            logger.warning("No tippers to sync")
            return 0

        # Get existing IDs in ChromaDB
        existing_ids = set()
        try:
            # Get all existing IDs (ChromaDB returns all if no filter)
            result = self.collection.get()
            existing_ids = set(result['ids']) if result['ids'] else set()
            logger.info(f"ChromaDB has {len(existing_ids)} existing tippers")
        except Exception as e:
            logger.warning(f"Could not get existing IDs: {e}")

        # Find new tippers
        new_tippers = []
        for tipper in tippers:
            tipper_id = str(tipper.get('id', ''))
            if tipper_id and tipper_id not in existing_ids:
                new_tippers.append(tipper)

        if not new_tippers:
            logger.info("No new tippers to add")
            logger.info("=" * 60)
            return 0

        logger.info(f"Found {len(new_tippers)} new tippers to add")

        # Process and upsert new tippers
        ids = []
        documents = []
        metadatas = []

        for i, tipper in enumerate(new_tippers):
            tipper_id = str(tipper.get('id', ''))

            if (i + 1) % 20 == 0 or i == 0:
                logger.info(f"Processing tipper {i + 1}/{len(new_tippers)}...")

            try:
                text = self.extract_tipper_text(tipper)
                metadata = self.prepare_tipper_metadata(tipper)

                ids.append(tipper_id)
                documents.append(text)
                metadatas.append(metadata)

            except Exception as e:
                logger.error(f"Failed to process tipper {tipper_id}: {e}")
                continue

        if not ids:
            logger.warning("No tippers processed successfully")
            return 0

        # Upsert to ChromaDB (generates embeddings automatically)
        logger.info(f"Upserting {len(ids)} tippers to ChromaDB...")
        try:
            # Generate embeddings
            embeddings = self._embedding_fn(documents)

            self.collection.upsert(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )
            logger.info(f"Successfully added {len(ids)} tippers")
            logger.info("=" * 60)
            logger.info("TIPPER SYNC COMPLETED")
            logger.info("=" * 60)
            return len(ids)

        except Exception as e:
            logger.error(f"Failed to upsert tippers: {e}", exc_info=True)
            return 0

    # -------------------------------------------------------------------------
    # Full rebuild (delete and recreate)
    # -------------------------------------------------------------------------
    def rebuild_index(self, days_back: int = 365) -> bool:
        """
        Full rebuild: Delete collection and recreate from scratch.

        Use this only when needed (schema change, corruption, etc.).
        Normal operation should use sync_tippers().

        Args:
            days_back: How far back to fetch

        Returns:
            True if successful
        """
        logger.info("=" * 60)
        logger.info("FULL INDEX REBUILD STARTING")
        logger.info("=" * 60)

        # Delete existing collection
        try:
            self.client.delete_collection(COLLECTION_NAME)
            self._collection = None  # Reset cached collection
            logger.info(f"Deleted existing collection: {COLLECTION_NAME}")
        except Exception as e:
            logger.warning(f"Could not delete collection (may not exist): {e}")

        # Fetch all tippers
        tippers = self.fetch_historical_tippers(days_back)
        if not tippers:
            logger.error("No tippers to index")
            return False

        logger.info(f"Processing {len(tippers)} tippers for indexing...")

        # Prepare data
        ids = []
        documents = []
        metadatas = []

        for i, tipper in enumerate(tippers):
            tipper_id = str(tipper.get('id', ''))

            if (i + 1) % 50 == 0 or i == 0:
                logger.info(f"Processing tipper {i + 1}/{len(tippers)}...")

            try:
                text = self.extract_tipper_text(tipper)
                metadata = self.prepare_tipper_metadata(tipper)

                ids.append(tipper_id)
                documents.append(text)
                metadatas.append(metadata)

            except Exception as e:
                logger.error(f"Failed to process tipper {tipper_id}: {e}")
                continue

        if not ids:
            logger.error("No tippers processed successfully")
            return False

        # Add to ChromaDB
        logger.info(f"Adding {len(ids)} tippers to ChromaDB...")
        try:
            # Generate embeddings
            embeddings = self._embedding_fn(documents)

            self.collection.add(
                ids=ids,
                documents=documents,
                metadatas=metadatas,
                embeddings=embeddings
            )

            logger.info(f"Indexed {len(ids)} tippers successfully")
            logger.info("=" * 60)
            logger.info("FULL INDEX REBUILD COMPLETED")
            logger.info("=" * 60)
            return True

        except Exception as e:
            logger.error(f"Failed to create index: {e}", exc_info=True)
            return False

    # -------------------------------------------------------------------------
    # Keyword search through metadata
    # -------------------------------------------------------------------------
    def _keyword_search(self, query_text: str, k: int = 10) -> List[dict]:
        """
        Search for tippers containing keywords from query text.

        Extracts important terms and searches title, tags in metadata.
        """
        # Common words to ignore
        STOP_WORDS = {
            'cti', 'threat', 'tipper', 'low', 'high', 'medium', 'informational',
            'action', 'attack', 'campaign', 'new', 'multi', 'stage', 'malware',
            'group', 'actor', 'targets', 'targeting', 'advisory', 'alert',
            'the', 'and', 'for', 'with', 'from', 'into', 'using', 'via',
            'this', 'that', 'these', 'those', 'has', 'have', 'are', 'were',
        }

        # Extract potential keywords
        keywords = set()

        # CamelCase words (malware names like BeaverTail, InvisibleFerret)
        camel_case = re.findall(r'\b[A-Z][a-z]+[A-Z][a-zA-Z]*\b', query_text)
        keywords.update(camel_case)

        # ALL_CAPS words (acronyms, codenames)
        all_caps = re.findall(r'\b[A-Z]{3,}\b', query_text)
        keywords.update(all_caps)

        # Capitalized words (proper nouns)
        capitalized = re.findall(r'\b[A-Z][a-z]{3,}\b', query_text)
        keywords.update(capitalized)

        # Filter stop words
        keywords = {kw for kw in keywords if kw.lower() not in STOP_WORDS}

        if not keywords:
            return []

        logger.debug(f"Keyword search for: {keywords}")

        # Get all documents from ChromaDB for keyword search
        try:
            result = self.collection.get(include=['metadatas'])
            if not result['ids']:
                return []

            matches = []
            for i, meta in enumerate(result['metadatas']):
                title = meta.get('title', '').lower()
                tags = meta.get('tags', '').lower()

                match_count = 0
                matched_keywords = []
                for kw in keywords:
                    kw_lower = kw.lower()
                    if kw_lower in title or kw_lower in tags:
                        match_count += 1
                        matched_keywords.append(kw)

                if match_count > 0:
                    matches.append({
                        'metadata': meta,
                        'keyword_matches': match_count,
                        'matched_keywords': matched_keywords,
                        'similarity_score': 0.9 + (0.01 * match_count),
                        'distance': 0.0,
                        'matched_content': f"Keyword match: {', '.join(matched_keywords)}"
                    })

            matches.sort(key=lambda x: x['keyword_matches'], reverse=True)
            return matches[:k]

        except Exception as e:
            logger.warning(f"Keyword search failed: {e}")
            return []

    # -------------------------------------------------------------------------
    # Search for similar tippers (HYBRID: keyword + vector)
    # -------------------------------------------------------------------------
    def find_similar_tippers(self, query_text: str, k: int = 5) -> List[dict]:
        """
        Find tippers similar to the given text using hybrid search.

        Combines:
        1. Keyword matching (exact term matches in title/tags)
        2. Vector similarity (semantic similarity via embeddings)

        Args:
            query_text: Text to search for (new tipper title/description)
            k: Number of similar tippers to return

        Returns:
            List of similar tipper metadata with similarity scores
        """
        # Check if collection has data
        try:
            count = self.collection.count()
            if count == 0:
                raise RuntimeError("No tippers in index. Run sync_tippers() first.")
            logger.info(f"Loaded tipper index with {count} tippers")
        except Exception as e:
            raise RuntimeError(f"Could not access tipper index: {e}")

        # 1. Keyword search
        keyword_results = self._keyword_search(query_text, k=k * 2)
        logger.debug(f"Keyword search found {len(keyword_results)} matches")

        # 2. Vector similarity search
        try:
            # Generate query embedding
            query_embedding = self._embedding_fn([query_text])[0]

            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=k * 2,
                include=['metadatas', 'documents', 'distances']
            )

            vector_results = []
            if results['ids'] and results['ids'][0]:
                for i, doc_id in enumerate(results['ids'][0]):
                    distance = results['distances'][0][i] if results['distances'] else 0
                    # Convert L2 distance to similarity (lower distance = more similar)
                    similarity = 1 / (1 + distance)

                    vector_results.append({
                        'metadata': results['metadatas'][0][i],
                        'similarity_score': round(similarity, 3),
                        'distance': round(distance, 3),
                        'matched_content': results['documents'][0][i][:500] if results['documents'] else ""
                    })

        except Exception as e:
            logger.warning(f"Vector search failed: {e}")
            vector_results = []

        # 3. Merge results: keyword matches first, then vector matches
        seen_ids = set()
        merged_results = []

        for result in keyword_results:
            tid = result['metadata'].get('id')
            if tid not in seen_ids:
                seen_ids.add(tid)
                merged_results.append(result)

        for result in vector_results:
            tid = result['metadata'].get('id')
            if tid not in seen_ids:
                seen_ids.add(tid)
                merged_results.append(result)

        return merged_results[:k]

    # -------------------------------------------------------------------------
    # Index stats
    # -------------------------------------------------------------------------
    def get_index_stats(self) -> dict:
        """Get statistics about the current index."""
        try:
            count = self.collection.count()
            return {
                'status': 'available',
                'tipper_count': count,
                'storage_path': self.chroma_path,
                'collection_name': COLLECTION_NAME
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}


# -------------------------------------------------------------------------
# CLI Entry Points
# -------------------------------------------------------------------------
def sync_tipper_index(days_back: int = 365) -> int:
    """Entry point for syncing tippers (adds new ones only)."""
    indexer = TipperIndexer()
    added = indexer.sync_tippers(days_back=days_back)
    print(f"Sync complete: {added} new tippers added")
    return added


def rebuild_tipper_index(days_back: int = 365) -> bool:
    """Entry point for full rebuild (deletes and recreates)."""
    indexer = TipperIndexer()
    success = indexer.rebuild_index(days_back=days_back)

    if success:
        stats = indexer.get_index_stats()
        print(f"Index rebuilt: {stats.get('tipper_count', 0)} tippers")
    else:
        print("Failed to rebuild tipper index")

    return success


def search_similar(query: str, k: int = 5) -> List[dict]:
    """CLI search for testing."""
    indexer = TipperIndexer()

    print(f"\nSearching for tippers similar to: '{query[:50]}...'\n")

    try:
        results = indexer.find_similar_tippers(query, k=k)

        print(f"Top {len(results)} similar tippers:\n")
        for i, result in enumerate(results, 1):
            meta = result['metadata']
            print(f"{i}. [{meta['id']}] {meta['title'][:60]}...")
            print(f"   Similarity: {result['similarity_score']:.1%}")
            print(f"   Tags: {meta.get('tags', 'N/A')[:50]}")
            print(f"   Created: {meta.get('created_date', 'N/A')[:10]}")
            print()

        return results

    except RuntimeError as e:
        print(f"Error: {e}")
        print("Run 'python -m src.components.tipper_indexer' first to sync tippers.")
        return []


def show_stats():
    """Show index statistics."""
    indexer = TipperIndexer()
    stats = indexer.get_index_stats()

    print("\nTipper Index Stats:")
    print("-" * 40)
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print()


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "search":
            query = " ".join(sys.argv[2:]) or "phishing campaign targeting finance"
            search_similar(query)
        elif command == "stats":
            show_stats()
        elif command == "rebuild":
            rebuild_tipper_index(days_back=365)
        else:
            print(f"Unknown command: {command}")
            print("Usage:")
            print("  python -m src.components.tipper_indexer           # Sync new tippers")
            print("  python -m src.components.tipper_indexer rebuild   # Full rebuild")
            print("  python -m src.components.tipper_indexer search <query>")
            print("  python -m src.components.tipper_indexer stats")
    else:
        # Default: sync tippers (incremental)
        sync_tipper_index(days_back=365)
