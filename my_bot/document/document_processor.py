# /services/document_processor.py
"""
Document Processing Module

This module handles RAG (Retrieval-Augmented Generation) document loading,
processing, and vector store management for the security operations bot.
"""

import os
import logging
from typing import List

from langchain_community.document_loaders import PyPDFDirectoryLoader, UnstructuredWordDocumentLoader, UnstructuredExcelLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_community.retrievers import BM25Retriever
from langchain.retrievers import EnsembleRetriever


class DocumentProcessor:
    """Handles document loading, processing, and vector store management"""

    def __init__(self, pdf_directory: str, faiss_index_path: str):
        self.pdf_directory = pdf_directory
        self.faiss_index_path = faiss_index_path
        self.vector_store = None
        self.retriever = None
        self.all_documents = []  # Store documents for BM25 retriever

        # Document processing configuration
        self.chunk_size = 1500
        self.chunk_overlap = 300
        self.retrieval_k = 5  # Number of documents to retrieve

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
                    # PyPDFDirectoryLoader loads all PDFs at once
                    loader = PyPDFDirectoryLoader(self.pdf_directory)
                    documents.extend(loader.load())
                    pdf_loaded = True
                    logging.debug(f"Loaded PDF documents from {self.pdf_directory}")
                elif ext in [".doc", ".docx"]:
                    loader = UnstructuredWordDocumentLoader(fpath)
                    doc_content = loader.load()

                    documents.extend(doc_content)
                    logging.debug(f"Loaded Word document: {fname}")
                elif ext in [".xlsx", ".xls"]:
                    loader = UnstructuredExcelLoader(fpath)
                    doc_content = loader.load()
                    documents.extend(doc_content)
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
            separators=["\n\n", "\n", ". ", "! ", "? ", " ", ""]  # Better splitting points
        )

        texts = text_splitter.split_documents(documents)
        logging.debug(f"Split into {len(texts)} text chunks with improved chunking strategy.")
        return texts

    def build_and_save_vector_store(self, embeddings) -> bool:
        """Build and save the vector store from documents"""
        if not os.path.exists(self.pdf_directory):
            logging.warning(f"PDF directory '{self.pdf_directory}' does not exist. Skipping vector store build.")
            return False

        files_in_dir = os.listdir(self.pdf_directory)
        if not files_in_dir:
            logging.warning(f"PDF directory '{self.pdf_directory}' is empty. Skipping vector store build.")
            return False

        logging.debug(f"Loading documents from: {self.pdf_directory}")
        documents = self.load_documents_from_folder()

        if not documents:
            logging.warning(f"No documents could be loaded from '{self.pdf_directory}'. Skipping vector store build.")
            return False

        logging.debug(f"Loaded {len(documents)} documents.")

        # Create text chunks
        texts = self.create_text_chunks(documents)

        # Store documents for BM25 retriever
        self.all_documents = texts

        # Create vector store
        logging.debug("Creating vector store with FAISS and Ollama embeddings...")
        try:
            self.vector_store = FAISS.from_documents(texts, embeddings)

            # Save the vector store
            os.makedirs(os.path.dirname(self.faiss_index_path), exist_ok=True)
            self.vector_store.save_local(self.faiss_index_path)
            logging.debug(f"Vector store saved to: {self.faiss_index_path}")
            return True

        except Exception as e:
            logging.error(f"Error creating or saving vector store: {e}", exc_info=True)
            return False

    def load_vector_store(self, embeddings) -> bool:
        """Load existing vector store from disk"""
        try:
            logging.debug(f"Loading existing FAISS index from: {self.faiss_index_path}")
            self.vector_store = FAISS.load_local(
                self.faiss_index_path,
                embeddings,
                allow_dangerous_deserialization=True
            )
            logging.debug("FAISS index loaded successfully.")

            # Also load documents for BM25 retriever if not already loaded
            if not self.all_documents:
                logging.debug("Loading documents for BM25 retriever...")
                documents = self.load_documents_from_folder()
                if documents:
                    self.all_documents = self.create_text_chunks(documents)
                    logging.debug(f"Loaded {len(self.all_documents)} documents for BM25")

            return True
        except Exception as e:
            logging.error(f"Error loading FAISS index: {e}", exc_info=True)
            return False

    def initialize_vector_store(self, embeddings) -> bool:
        """Initialize vector store - load existing or build new, auto-rebuild if docs changed"""
        # Check if we need to rebuild due to new/changed documents
        if os.path.exists(self.faiss_index_path):
            if self._should_rebuild_index():
                logging.debug("🔄 New or changed documents detected, rebuilding vector store...")
                if self.build_and_save_vector_store(embeddings):
                    return self.load_vector_store(embeddings)
                else:
                    logging.error("Failed to rebuild, attempting to load existing index...")

            if self.load_vector_store(embeddings):
                return True
            else:
                logging.debug("Failed to load existing vector store, rebuilding...")
                if self.build_and_save_vector_store(embeddings):
                    return self.load_vector_store(embeddings)
        else:
            logging.debug(f"FAISS index not found at {self.faiss_index_path}. Building new vector store.")
            if self.build_and_save_vector_store(embeddings):
                return self.load_vector_store(embeddings)

        return False

    def _should_rebuild_index(self) -> bool:
        """Check if vector store should be rebuilt due to document changes"""
        if not os.path.exists(self.faiss_index_path):
            return True

        # Get index modification time
        index_mtime = os.path.getmtime(self.faiss_index_path + '/index.faiss')

        # Check if any document is newer than the index
        for file in os.listdir(self.pdf_directory):
            if file.endswith(('.pdf', '.docx', '.doc', '.xlsx', '.xls')):
                file_path = os.path.join(self.pdf_directory, file)
                if os.path.getmtime(file_path) > index_mtime:
                    logging.debug(f"📄 Newer document found: {file}")
                    return True

        return False

    def create_retriever(self):
        """Create hybrid retriever combining vector and keyword search"""
        if not self.vector_store:
            logging.error("Vector store not initialized")
            return None

        if not self.all_documents:
            logging.error("Documents not loaded for BM25 retriever")
            return None

        try:
            # Create vector retriever
            vector_retriever = self.vector_store.as_retriever(search_kwargs={"k": self.retrieval_k})

            # Create BM25 keyword retriever
            bm25_retriever = BM25Retriever.from_documents(self.all_documents)
            bm25_retriever.k = self.retrieval_k

            # Create hybrid ensemble retriever (70% vector, 30% keyword)
            self.retriever = EnsembleRetriever(
                retrievers=[vector_retriever, bm25_retriever],
                weights=[0.65, 0.35]
            )

            logging.debug("Hybrid retriever created successfully (65% vector + 35% BM25)")
            return self.retriever

        except Exception as e:
            logging.error(f"Failed to create hybrid retriever: {e}")
            # Fallback to vector-only retriever
            self.retriever = self.vector_store.as_retriever(search_kwargs={"k": self.retrieval_k})
            logging.debug("Falling back to vector-only retriever")
            return self.retriever

    def create_rag_tool(self):
        """Create RAG tool for document search with source attribution"""
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
                response_parts = []
                sources_content = {}

                for doc in docs:
                    source_file = os.path.basename(doc.metadata.get('source', 'Unknown document'))
                    if source_file not in sources_content:
                        sources_content[source_file] = []
                    sources_content[source_file].append(doc.page_content.strip())

                # Simple approach: show top sources in order retrieved
                for source_file, contents in sources_content.items():
                    combined_content = "\n\n".join(contents[:2])  # Top 2 chunks per source
                    response_parts.append(f"📄 **From {source_file}:**\n{combined_content}")

                # Join all sources (limit to top 10 to catch more relevant docs)
                result = "\n\n" + "\n\n".join(response_parts[:10])

                # Add source summary
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
        """Test the document search functionality directly"""
        if not self.retriever:
            return "Vector store not initialized"

        try:
            # Test direct retrieval
            docs = self.retriever.invoke(query)
            if docs:
                result = f"Found {len(docs)} relevant documents for query '{query}':\n\n"
                for i, doc in enumerate(docs[:3], 1):  # Show top 3
                    content = doc.page_content[:200] + "..." if len(doc.page_content) > 200 else doc.page_content
                    source = doc.metadata.get('source', 'Unknown')
                    result += f"{i}. Source: {source}\nContent: {content}\n\n"
                return result
            else:
                return f"No documents found for query '{query}'"
        except Exception as e:
            return f"Error testing document search: {e}"

    def force_rebuild(self, embeddings) -> bool:
        """Force rebuild the vector store from scratch"""
        logging.debug("Force rebuilding vector store...")

        # Remove existing index if it exists
        if os.path.exists(self.faiss_index_path):
            try:
                import shutil
                shutil.rmtree(self.faiss_index_path)
                logging.debug("Removed existing FAISS index")
            except Exception as e:
                logging.error(f"Failed to remove existing index: {e}")

        # Reset internal state
        self.vector_store = None
        self.retriever = None

        # Rebuild vector store
        success = self.build_and_save_vector_store(embeddings)
        if success:
            return self.initialize_vector_store(embeddings) and self.create_retriever() is not None
        return False

    def get_document_stats(self) -> dict:
        """Get statistics about loaded documents"""
        if not self.vector_store:
            return {"status": "not_initialized"}

        try:
            # Get vector store statistics
            index = self.vector_store.index
            total_vectors = index.ntotal if hasattr(index, 'ntotal') else 0

            return {
                "status": "initialized",
                "total_vectors": total_vectors,
                "retrieval_k": self.retrieval_k,
                "chunk_size": self.chunk_size,
                "chunk_overlap": self.chunk_overlap,
                "index_path": self.faiss_index_path,
                "documents_directory": self.pdf_directory
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def update_retrieval_settings(self, k: int = None, chunk_size: int = None, chunk_overlap: int = None):
        """Update retrieval settings"""
        if k is not None:
            self.retrieval_k = k
            if self.retriever:
                self.retriever = self.vector_store.as_retriever(search_kwargs={"k": self.retrieval_k})

        if chunk_size is not None:
            self.chunk_size = chunk_size

        if chunk_overlap is not None:
            self.chunk_overlap = chunk_overlap

        logging.debug(f"Updated retrieval settings: k={self.retrieval_k}, chunk_size={self.chunk_size}, chunk_overlap={self.chunk_overlap}")
