# /services/document_processor.py
"""
Document Processing Module

This module handles RAG (Retrieval-Augmented Generation) document loading,
processing, and vector store management for the security operations bot.

Uses ChromaDB for persistent vector storage.
"""

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any, List, Optional

import chromadb
import requests
from langchain_community.document_loaders import (
    PyPDFDirectoryLoader,
    UnstructuredExcelLoader,
    UnstructuredWordDocumentLoader,
)
from langchain_community.retrievers import BM25Retriever
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever

# Handle different LangChain versions (0.3.x vs 1.0.x)
try:
    from langchain.text_splitter import RecursiveCharacterTextSplitter
except ImportError:
    from langchain_text_splitters import RecursiveCharacterTextSplitter

# Try to import EnsembleRetriever - optional, will fallback to vector-only if unavailable
EnsembleRetriever = None
try:
    from langchain.retrievers import EnsembleRetriever
except ImportError:
    try:
        from langchain_community.retrievers import EnsembleRetriever
    except ImportError:
        logging.warning("EnsembleRetriever not available, will use vector-only retrieval")


# Collection name for documents
DOCUMENTS_COLLECTION = "local_documents"


class OllamaEmbeddingFunction:
    """Custom embedding function using Ollama API with batch support."""

    def __init__(self, model: str = "nomic-embed-text", batch_size: int = 50):
        self.model = model
        self.api_url = "http://localhost:11434/api/embed"
        self.batch_size = batch_size  # Max texts per API call

    def __call__(self, input: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts using batch API calls."""
        if not input:
            return []

        # For small inputs, use single batch call
        if len(input) <= self.batch_size:
            return self._embed_batch(input)

        # For large inputs, process in parallel batches
        from concurrent.futures import ThreadPoolExecutor, as_completed

        all_embeddings = [None] * len(input)  # Pre-allocate to maintain order
        batches = []

        # Split into batches with their original indices
        for i in range(0, len(input), self.batch_size):
            batch_texts = input[i:i + self.batch_size]
            batches.append((i, batch_texts))

        logging.info(f"Processing {len(input)} texts in {len(batches)} parallel batches...")

        # Process batches in parallel (limit workers to avoid overwhelming Ollama)
        max_workers = min(4, len(batches))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_batch = {
                executor.submit(self._embed_batch, batch_texts): (start_idx, batch_texts)
                for start_idx, batch_texts in batches
            }

            for future in as_completed(future_to_batch):
                start_idx, batch_texts = future_to_batch[future]
                try:
                    batch_embeddings = future.result()
                    for j, embedding in enumerate(batch_embeddings):
                        all_embeddings[start_idx + j] = embedding
                except Exception as e:
                    logging.error(f"Batch embedding failed at index {start_idx}: {e}")
                    # Fallback: try individual embeddings for failed batch
                    for j, text in enumerate(batch_texts):
                        try:
                            all_embeddings[start_idx + j] = self._embed_single(text)
                        except Exception as inner_e:
                            logging.error(f"Single embedding fallback failed: {inner_e}")
                            raise

        return all_embeddings

    def _embed_batch(self, texts: List[str], max_retries: int = 3) -> List[List[float]]:
        """Generate embeddings for a batch of texts in a single API call."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json={"model": self.model, "input": texts},
                    timeout=120  # Longer timeout for batches
                )
                response.raise_for_status()
                result = response.json()
                return result["embeddings"]
            except Exception as e:
                if attempt < max_retries - 1:
                    logging.warning(f"Batch embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Failed to embed batch of {len(texts)} texts: {e}")

    def _embed_single(self, text: str, max_retries: int = 3) -> List[float]:
        """Generate embedding for a single text (fallback method)."""
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    self.api_url,
                    json={"model": self.model, "input": text},
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                return result["embeddings"][0]
            except Exception as e:
                if attempt < max_retries - 1:
                    logging.warning(f"Embedding failed (attempt {attempt + 1}): {e}")
                    time.sleep(2)
                else:
                    raise RuntimeError(f"Failed to embed text: {e}")


class ChromaRetriever(BaseRetriever):
    """Custom retriever for ChromaDB that implements LangChain's BaseRetriever interface."""

    collection: Any  # ChromaDB collection
    embedding_fn: OllamaEmbeddingFunction
    k: int = 5

    class Config:
        arbitrary_types_allowed = True

    def _get_relevant_documents(self, query: str) -> List[Document]:
        """Retrieve relevant documents from ChromaDB."""
        try:
            # Generate query embedding
            query_embedding = self.embedding_fn([query])[0]

            # Query ChromaDB
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=self.k,
                include=['documents', 'metadatas', 'distances']
            )

            # Convert to LangChain Documents
            documents = []
            if results['ids'] and results['ids'][0]:
                for i, doc_id in enumerate(results['ids'][0]):
                    content = results['documents'][0][i] if results['documents'] else ""
                    metadata = results['metadatas'][0][i] if results['metadatas'] else {}
                    documents.append(Document(page_content=content, metadata=metadata))

            return documents

        except Exception as e:
            logging.error(f"ChromaDB retrieval error: {e}")
            return []


class DocumentProcessor:
    """Handles document loading, processing, and vector store management using ChromaDB"""

    def __init__(self, pdf_directory: str, chroma_path: str = None):
        self.pdf_directory = pdf_directory

        # Set ChromaDB path (default to same location as old FAISS index)
        if chroma_path is None:
            # Convert old faiss_index_path to chroma path
            chroma_path = str(Path(pdf_directory).parent / "chroma_documents")
        self.chroma_path = chroma_path

        self._client: Optional[chromadb.PersistentClient] = None
        self._collection = None
        self._embedding_fn = OllamaEmbeddingFunction()

        self.retriever = None
        self.all_documents = []  # Store documents for BM25 retriever

        # Document processing configuration
        self.chunk_size = 1500
        self.chunk_overlap = 300
        self.retrieval_k = 5

    @property
    def client(self) -> chromadb.PersistentClient:
        """Lazy-load ChromaDB client."""
        if self._client is None:
            self._client = chromadb.PersistentClient(path=self.chroma_path)
        return self._client

    @property
    def collection(self):
        """Get or create the documents collection."""
        if self._collection is None:
            self._collection = self.client.get_or_create_collection(
                name=DOCUMENTS_COLLECTION,
                metadata={"description": "Local document embeddings for RAG"}
            )
        return self._collection

    @property
    def vector_store(self):
        """Compatibility property - returns collection count > 0."""
        try:
            return self.collection.count() > 0
        except Exception:
            return False

    def _generate_doc_id(self, content: str, source: str) -> str:
        """Generate a unique ID for a document chunk."""
        hash_input = f"{source}:{content[:200]}"
        return hashlib.md5(hash_input.encode()).hexdigest()

    def load_documents_from_folder(self) -> List:
        """Load documents from the specified folder"""
        documents = []
        pdf_loaded = False

        if not os.path.exists(self.pdf_directory):
            logging.warning(f"Folder does not exist: {self.pdf_directory}")
            return documents

        for fname in os.listdir(self.pdf_directory):
            fpath = os.path.join(self.pdf_directory, fname)
            if not os.path.isfile(fpath):
                continue

            ext = os.path.splitext(fname)[1].lower()

            try:
                if ext == ".pdf" and not pdf_loaded:
                    loader = PyPDFDirectoryLoader(self.pdf_directory)
                    documents.extend(loader.load())
                    pdf_loaded = True
                    logging.debug(f"Loaded PDF documents from {self.pdf_directory}")
                elif ext in [".doc", ".docx"]:
                    loader = UnstructuredWordDocumentLoader(fpath)
                    documents.extend(loader.load())
                    logging.debug(f"Loaded Word document: {fname}")
                elif ext in [".xlsx", ".xls"]:
                    loader = UnstructuredExcelLoader(fpath)
                    documents.extend(loader.load())
                    logging.debug(f"Loaded Excel document: {fname}")
            except Exception as e:
                logging.error(f"Failed to load {fname}: {e}")

        return documents

    def create_text_chunks(self, documents: List) -> List:
        """Split documents into optimized text chunks"""
        if not documents:
            return []

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.chunk_size,
            chunk_overlap=self.chunk_overlap,
            length_function=len,
            separators=["\n\n", "\n", ". ", "! ", "? ", " ", ""]
        )

        texts = text_splitter.split_documents(documents)
        logging.debug(f"Split into {len(texts)} text chunks.")
        return texts

    def build_and_save_vector_store(self, embeddings=None, batch_size: int = 10) -> bool:
        """Build and save the vector store from documents (ChromaDB handles persistence)."""
        if not os.path.exists(self.pdf_directory):
            logging.warning(f"PDF directory '{self.pdf_directory}' does not exist.")
            return False

        files_in_dir = [f for f in os.listdir(self.pdf_directory)
                        if f.endswith(('.pdf', '.docx', '.doc', '.xlsx', '.xls'))]
        if not files_in_dir:
            logging.warning(f"PDF directory '{self.pdf_directory}' has no documents.")
            return False

        logging.debug(f"Loading documents from: {self.pdf_directory}")
        documents = self.load_documents_from_folder()

        if not documents:
            logging.warning(f"No documents could be loaded from '{self.pdf_directory}'.")
            return False

        logging.debug(f"Loaded {len(documents)} documents.")

        # Create text chunks
        texts = self.create_text_chunks(documents)
        self.all_documents = texts

        # Get existing IDs to avoid duplicates
        existing_ids = set()
        try:
            result = self.collection.get()
            existing_ids = set(result['ids']) if result['ids'] else set()
            logging.debug(f"ChromaDB has {len(existing_ids)} existing chunks")
        except Exception as e:
            logging.warning(f"Could not get existing IDs: {e}")

        # Prepare new chunks
        ids = []
        documents_content = []
        metadatas = []

        total_chunks = len(texts)
        print(f"   Processing {total_chunks} text chunks...", flush=True)

        for i, doc in enumerate(texts):
            doc_id = self._generate_doc_id(doc.page_content, doc.metadata.get('source', ''))

            # Skip if already indexed
            if doc_id in existing_ids:
                continue

            if (i + 1) % 20 == 0 or i == 0:
                print(f"   Processing chunk {i + 1}/{total_chunks}...", flush=True)

            ids.append(doc_id)
            documents_content.append(doc.page_content)
            metadatas.append(doc.metadata)

        if not ids:
            logging.info("No new chunks to add")
            return True

        # Generate embeddings and upsert to ChromaDB
        print(f"   Embedding and upserting {len(ids)} new chunks...", flush=True)
        try:
            embeddings_list = self._embedding_fn(documents_content)

            self.collection.upsert(
                ids=ids,
                documents=documents_content,
                metadatas=metadatas,
                embeddings=embeddings_list
            )

            logging.debug(f"Added {len(ids)} chunks to ChromaDB")
            return True

        except Exception as e:
            logging.error(f"Error adding to ChromaDB: {e}", exc_info=True)
            return False

    def load_vector_store(self, embeddings=None) -> bool:
        """Load existing vector store (ChromaDB loads automatically)."""
        try:
            count = self.collection.count()
            if count == 0:
                logging.warning("ChromaDB collection is empty")
                return False

            logging.debug(f"ChromaDB collection has {count} chunks")

            # Load documents for BM25 retriever if not already loaded
            if not self.all_documents:
                logging.debug("Loading documents for BM25 retriever...")
                documents = self.load_documents_from_folder()
                if documents:
                    self.all_documents = self.create_text_chunks(documents)
                    logging.debug(f"Loaded {len(self.all_documents)} documents for BM25")

            return True

        except Exception as e:
            logging.error(f"Error loading ChromaDB: {e}", exc_info=True)
            return False

    def initialize_vector_store(self, embeddings=None) -> bool:
        """Initialize vector store - load existing or build new."""
        # Check if we need to rebuild due to new/changed documents
        if self._should_rebuild_index():
            logging.debug("New or changed documents detected, syncing to ChromaDB...")
            self.build_and_save_vector_store(embeddings)

        return self.load_vector_store(embeddings)

    def _should_rebuild_index(self) -> bool:
        """Check if vector store should be rebuilt due to document changes."""
        try:
            count = self.collection.count()
            if count == 0:
                return True

            # Get the latest modification time of documents
            latest_doc_mtime = 0
            for file in os.listdir(self.pdf_directory):
                if file.endswith(('.pdf', '.docx', '.doc', '.xlsx', '.xls')):
                    file_path = os.path.join(self.pdf_directory, file)
                    mtime = os.path.getmtime(file_path)
                    if mtime > latest_doc_mtime:
                        latest_doc_mtime = mtime

            # Check ChromaDB metadata for last sync time
            # For simplicity, always sync if documents exist (upsert handles duplicates)
            return latest_doc_mtime > 0

        except Exception:
            return True

    def create_retriever(self):
        """Create hybrid retriever combining vector and keyword search."""
        try:
            count = self.collection.count()
            if count == 0:
                logging.error("ChromaDB collection is empty")
                return None
        except Exception as e:
            logging.error(f"ChromaDB not initialized: {e}")
            return None

        if not self.all_documents:
            logging.error("Documents not loaded for BM25 retriever")
            return None

        try:
            # Create ChromaDB vector retriever
            vector_retriever = ChromaRetriever(
                collection=self.collection,
                embedding_fn=self._embedding_fn,
                k=self.retrieval_k
            )

            # Create hybrid ensemble retriever if available
            if EnsembleRetriever is not None:
                bm25_retriever = BM25Retriever.from_documents(self.all_documents)
                bm25_retriever.k = self.retrieval_k

                self.retriever = EnsembleRetriever(
                    retrievers=[vector_retriever, bm25_retriever],
                    weights=[0.65, 0.35]
                )
                logging.debug("Hybrid retriever created (65% vector + 35% BM25)")
            else:
                self.retriever = vector_retriever
                logging.debug("Using vector-only retriever")

            return self.retriever

        except Exception as e:
            logging.error(f"Failed to create retriever: {e}")
            self.retriever = ChromaRetriever(
                collection=self.collection,
                embedding_fn=self._embedding_fn,
                k=self.retrieval_k
            )
            return self.retriever

    def create_rag_tool(self):
        """Create RAG tool for document search with source attribution."""
        if not self.retriever:
            logging.error("Retriever not initialized")
            return None

        from langchain_core.tools import tool

        @tool
        def search_local_documents(query: str) -> str:
            """
            Searches and returns information from local PDF and Word documents with source attribution.
            Use this for questions about policies, reports, or specific documented information.
            Returns relevant content from documents with clear source references.
            """
            try:
                docs = self.retriever.invoke(query)

                if not docs:
                    return f"No relevant documents found for query: '{query}'"

                # Build response with source attribution
                sources_content = {}

                for doc in docs:
                    source_file = os.path.basename(doc.metadata.get('source', 'Unknown document'))
                    if source_file not in sources_content:
                        sources_content[source_file] = []
                    sources_content[source_file].append(doc.page_content.strip())

                response_parts = []
                for source_file, contents in sources_content.items():
                    combined_content = "\n\n".join(contents[:4])
                    response_parts.append(f"**From {source_file}:**\n{combined_content}")

                result = "\n\n" + "\n\n".join(response_parts[:10])

                source_list = list(sources_content.keys())
                if len(source_list) == 1:
                    result += f"\n\n**Source:** {source_list[0]}"
                else:
                    result += f"\n\n**Sources:** {', '.join(source_list[:10])}"
                    if len(source_list) > 10:
                        result += f" and {len(source_list) - 10} other documents"

                return result

            except Exception as e:
                logging.error(f"Error in document search: {e}")
                return f"Error searching documents: {str(e)}"

        return search_local_documents

    def test_document_search(self, query: str = "network access control") -> str:
        """Test the document search functionality directly."""
        if not self.retriever:
            return "Retriever not initialized"

        try:
            docs = self.retriever.invoke(query)
            if docs:
                result = f"Found {len(docs)} relevant documents for query '{query}':\n\n"
                for i, doc in enumerate(docs[:3], 1):
                    content = doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content
                    source = doc.metadata.get('source', 'Unknown')
                    result += f"{i}. Source: {source}\nContent: {content}\n\n"
                return result
            else:
                return f"No documents found for query '{query}'"
        except Exception as e:
            return f"Error testing document search: {e}"

    def force_rebuild(self, embeddings=None) -> bool:
        """Force rebuild the vector store from scratch."""
        logging.debug("Force rebuilding vector store...")

        # Delete existing collection
        try:
            self.client.delete_collection(DOCUMENTS_COLLECTION)
            self._collection = None
            logging.debug("Deleted existing ChromaDB collection")
        except Exception as e:
            logging.warning(f"Could not delete collection: {e}")

        # Reset internal state
        self.retriever = None
        self.all_documents = []

        # Rebuild
        success = self.build_and_save_vector_store(embeddings)
        if success:
            return self.initialize_vector_store(embeddings) and self.create_retriever() is not None
        return False

    def get_document_stats(self) -> dict:
        """Get statistics about loaded documents."""
        try:
            count = self.collection.count()
            return {
                "status": "initialized" if count > 0 else "empty",
                "total_chunks": count,
                "retrieval_k": self.retrieval_k,
                "chunk_size": self.chunk_size,
                "chunk_overlap": self.chunk_overlap,
                "chroma_path": self.chroma_path,
                "documents_directory": self.pdf_directory
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def update_retrieval_settings(self, k: int = None, chunk_size: int = None, chunk_overlap: int = None):
        """Update retrieval settings."""
        if k is not None:
            self.retrieval_k = k
            if self.retriever and hasattr(self.retriever, 'k'):
                self.retriever.k = k

        if chunk_size is not None:
            self.chunk_size = chunk_size

        if chunk_overlap is not None:
            self.chunk_overlap = chunk_overlap

        logging.debug(f"Updated settings: k={self.retrieval_k}, chunk_size={self.chunk_size}")

    # Compatibility properties for old faiss_index_path references
    @property
    def faiss_index_path(self) -> str:
        """Compatibility property - returns chroma_path."""
        return self.chroma_path

    @faiss_index_path.setter
    def faiss_index_path(self, value: str):
        """Compatibility setter - updates chroma_path."""
        self.chroma_path = value
