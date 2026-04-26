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

from my_bot.utils.embedding_function import OpenAIEmbeddingFunction

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
        self._embedding_batch_size = 10  # Max texts per API call

    def _get_embedding(self, text: str) -> List[float]:
        """Get embedding for a single text."""
        return OpenAIEmbeddingFunction()([text])[0]

    def _get_embeddings_batch(self, texts: List[str]) -> List[List[float]]:
        """Get embeddings for a batch of texts."""
        if not texts:
            return []
        return OpenAIEmbeddingFunction()(texts)

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
        """Build the vector store from SQLite DB (preferred) or Excel (fallback)."""
        documents, ids = self._load_documents_from_sqlite()
        if not documents:
            logger.info("SQLite DB empty or missing, falling back to Excel")
            documents, ids = self._load_documents_from_excel()

        if not documents:
            logger.warning("No contacts found in SQLite or Excel")
            return

        embeddings = []
        logger.info(f"Generating embeddings for {len(documents)} contact entries in batches...")

        for i in range(0, len(documents), self._embedding_batch_size):
            batch = documents[i:i + self._embedding_batch_size]
            batch_embeddings = self._get_embeddings_batch(batch)
            embeddings.extend(batch_embeddings)

            if len(documents) > self._embedding_batch_size:
                logger.info(f"  Processed {min(i + self._embedding_batch_size, len(documents))}/{len(documents)} embeddings...")

        self.collection.add(
            documents=documents,
            ids=ids,
            embeddings=embeddings
        )
        logger.info(f"Added {len(documents)} contacts to vector store")

    def _load_documents_from_sqlite(self):
        """Load contact documents from the SQLite database.

        Pulls from BOTH the legacy `contacts` table (DnR escalation paths) and
        the `sheet_rows` table (Regional Contact List worksheets), so the
        the security assistant bot contacts tool can search across all of them.
        """
        try:
            import json
            from src.components.web.escalation_contacts_handler import DB_PATH, _get_connection
            if not DB_PATH.exists():
                return [], []

            documents = []
            ids = []
            with _get_connection() as conn:
                rows = conn.execute(
                    "SELECT id, region, team, name, title, email, phone, comments FROM contacts ORDER BY region, sort_order, team, name"
                ).fetchall()

                for row in rows:
                    r = dict(row)
                    parts = [r["name"]]
                    if r["title"]:
                        parts.append(r["title"])
                    if r["email"]:
                        parts.append(r["email"])
                    if r["phone"]:
                        parts.append(r["phone"])
                    doc_text = f"Region/Sheet: {r['region']}. Team: {r['team']}. Contact: {' | '.join(parts)}"
                    if r.get("comments"):
                        doc_text += f". Notes: {r['comments']}"
                    documents.append(doc_text)
                    ids.append(f"contact_{r['id']}")

                # Also pull rows from worksheet tabs (Regional Contact List)
                sheet_rows = conn.execute("""
                    SELECT sr.id, sr.values_json, st.sheet_name, st.columns_json, st.is_doc
                    FROM sheet_rows sr
                    JOIN sheet_tabs st ON sr.sheet_id = st.id
                    ORDER BY st.display_order, sr.row_index
                """).fetchall()

                for sr in sheet_rows:
                    s = dict(sr)
                    if s["is_doc"]:
                        # Doc sheets are free-text process notes — index as-is
                        try:
                            text = " ".join(json.loads(s["values_json"]))
                        except Exception:
                            text = ""
                        if text.strip():
                            documents.append(f"Sheet: {s['sheet_name']}. {text}")
                            ids.append(f"sheet_row_{s['id']}")
                        continue

                    try:
                        cols = json.loads(s["columns_json"])
                        vals = json.loads(s["values_json"])
                    except Exception:
                        continue
                    parts = []
                    for col, val in zip(cols, vals):
                        v = (val or "").strip() if isinstance(val, str) else val
                        if v:
                            parts.append(f"{col.strip()}: {v}")
                    if not parts:
                        continue
                    doc_text = f"Sheet: {s['sheet_name']}. {' | '.join(parts)}"
                    documents.append(doc_text)
                    ids.append(f"sheet_row_{s['id']}")

            if not documents:
                return [], []

            logger.info(f"Loaded {len(documents)} contact entries from SQLite (contacts + sheet_rows)")
            return documents, ids
        except Exception as e:
            logger.warning(f"Could not load from SQLite: {e}")
            return [], []

    def _load_documents_from_excel(self):
        """Load contact documents from the Excel file (fallback)."""
        if not CONTACTS_FILE.exists():
            return [], []

        xl = pd.ExcelFile(CONTACTS_FILE)
        documents = []
        ids = []
        doc_counter = 0

        for sheet_name in xl.sheet_names:
            df = pd.read_excel(CONTACTS_FILE, sheet_name=sheet_name)
            last_group_name = ""

            for idx, row in df.iterrows():
                parts = []
                first_col_value = ""

                for col_idx, val in enumerate(row.values):
                    if pd.notna(val):
                        val_str = str(val).strip()
                        if val_str:
                            parts.append(val_str)
                            if col_idx == 0:
                                first_col_value = val_str

                if first_col_value:
                    last_group_name = first_col_value
                elif last_group_name and parts:
                    parts.insert(0, f"({last_group_name})")

                if parts:
                    doc_text = f"Region/Sheet: {sheet_name}. Contact: {' | '.join(parts)}"
                    doc_id = f"contact_{doc_counter}"
                    doc_counter += 1
                    documents.append(doc_text)
                    ids.append(doc_id)

        return documents, ids

    def search(self, query: str, n_results: int = 10) -> List[str]:
        """Search for contacts matching the query using hybrid approach.

        When any primary match has a "Notes:" field, expand by running a vector
        search using the notes text as the query and append semantically-similar
        contacts. This surfaces cross-referenced teams (e.g. Notes says "copy
        ASIA-CIRT too" → "ASIA-CIRT DL" row is pulled in) without having to
        dump the full directory into the LLM prompt.
        """
        if not self._initialized:
            self.initialize()

        try:
            all_docs = self.collection.get()['documents']
            query_lower = query.lower()
            keyword_matches = [d for d in all_docs if query_lower in d.lower()]

            if keyword_matches:
                primary = keyword_matches[:n_results]
            else:
                query_embedding = self._get_embedding(query)
                results = self.collection.query(
                    query_embeddings=[query_embedding],
                    n_results=n_results,
                )
                primary = results['documents'][0] if results['documents'] else []

            # Vector-expand on any Notes: fields in the primary results
            notes_texts = []
            for d in primary:
                idx = d.find("Notes:")
                if idx != -1:
                    notes_texts.append(d[idx + len("Notes:"):].strip())

            if not notes_texts:
                return primary

            combined_notes = " ".join(notes_texts)
            notes_embedding = self._get_embedding(combined_notes)
            note_results = self.collection.query(
                query_embeddings=[notes_embedding],
                n_results=n_results,
            )
            note_docs = note_results['documents'][0] if note_results['documents'] else []

            seen = set(primary)
            expanded = list(primary)
            for d in note_docs:
                if d not in seen:
                    expanded.append(d)
                    seen.add(d)
            return expanded
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

    def _build_contact_doc(self, row_dict):
        """Build the doc text for a single contact row — must match _load_documents_from_sqlite."""
        parts = [row_dict["name"]]
        if row_dict.get("title"):
            parts.append(row_dict["title"])
        if row_dict.get("email"):
            parts.append(row_dict["email"])
        if row_dict.get("phone"):
            parts.append(row_dict["phone"])
        doc_text = f"Region/Sheet: {row_dict['region']}. Team: {row_dict['team']}. Contact: {' | '.join(parts)}"
        if row_dict.get("comments"):
            doc_text += f". Notes: {row_dict['comments']}"
        return doc_text

    def upsert_contact(self, contact_id: int) -> bool:
        """Upsert a single contact row by ID (re-embeds only that row).

        If the contact no longer exists in SQLite, removes it from the vector store.
        """
        if not self._initialized:
            self.initialize()
        try:
            from src.components.web.escalation_contacts_handler import _get_connection
            with _get_connection() as conn:
                row = conn.execute(
                    "SELECT id, region, team, name, title, email, phone, comments FROM contacts WHERE id = ?",
                    (contact_id,),
                ).fetchone()
            if not row:
                return self.remove_contact(contact_id)

            doc_text = self._build_contact_doc(dict(row))
            embedding = self._get_embedding(doc_text)
            self.collection.upsert(
                ids=[f"contact_{contact_id}"],
                documents=[doc_text],
                embeddings=[embedding],
            )
            logger.info(f"Upserted contact {contact_id} in vector store")
            return True
        except Exception as e:
            logger.error(f"Failed to upsert contact {contact_id}: {e}", exc_info=True)
            return False

    def remove_contact(self, contact_id: int) -> bool:
        """Remove a single contact from the vector store by ID."""
        if not self._initialized:
            self.initialize()
        try:
            self.collection.delete(ids=[f"contact_{contact_id}"])
            logger.info(f"Removed contact {contact_id} from vector store")
            return True
        except Exception as e:
            logger.error(f"Failed to remove contact {contact_id}: {e}", exc_info=True)
            return False


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

        context = "Here are the relevant contacts from the escalation paths document:\n\n"
        for i, contact in enumerate(contacts, 1):
            context += f"{i}. {contact}\n"

        prompt = f"""{context}

Based on the contacts above, answer this query: "{query}"

Format each contact like this (make the values bold, not the labels):
- Name: **[Full Name]**
  Email: [<redacted-email>]

Include phone number only if available. Be concise.

The list above may contain both the primary contact(s) for the query AND
additional contacts that were pulled in because a primary contact's "Notes:"
field references them (e.g. "copy ASIA-CIRT too", "escalate to X first").
If you see such a reference, include the matching contact from the list in
your answer with a short line explaining the relationship (e.g. "Copy on
escalation, per note on AMthe company")."""

        # Use shared LLM instance to go through the serializer
        from my_bot.core.state_manager import get_state_manager
        state_manager = get_state_manager()
        llm = state_manager.llm

        response = llm.invoke(prompt)
        meta = response.response_metadata or {}

        from my_bot.utils.llm_factory import extract_token_metrics
        m = extract_token_metrics(meta)
        input_tokens = m['input_tokens']
        output_tokens = m['output_tokens']
        prompt_time = m['prompt_time']
        generation_time = m['generation_time']
        tokens_per_sec = output_tokens / generation_time if generation_time > 0 else 0.0

        llm_response = (response.content or '').strip()
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
