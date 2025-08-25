# /services/document_processor.py
"""
Document Processing Module

This module handles RAG (Retrieval-Augmented Generation) document loading,
processing, and vector store management for the security operations bot.
"""

import os
import logging
from typing import List, Optional

from langchain_community.document_loaders import PyPDFDirectoryLoader, UnstructuredWordDocumentLoader, UnstructuredExcelLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain.tools.retriever import create_retriever_tool


class DocumentProcessor:
    """Handles document loading, processing, and vector store management"""

    def __init__(self, pdf_directory: str, faiss_index_path: str):
        self.pdf_directory = pdf_directory
        self.faiss_index_path = faiss_index_path
        self.vector_store = None
        self.retriever = None
        
        # Document processing configuration
        self.chunk_size = 1500
        self.chunk_overlap = 300
        self.retrieval_k = 5  # Number of documents to retrieve
        
    def verify_specific_document_loading(self, target_doc: str = "GDnR_Blocking_Network_Access_Control _10022024.docx") -> bool:
        """Verify that a specific document is loaded and indexed properly"""
        doc_path = os.path.join(self.pdf_directory, target_doc)
        
        logging.info(f"Checking specific document: {target_doc}")
        
        if not os.path.exists(doc_path):
            logging.error(f"Target document not found: {doc_path}")
            return False
            
        try:
            # Test loading the specific document
            loader = UnstructuredWordDocumentLoader(doc_path)
            docs = loader.load()
            
            if docs:
                content = docs[0].page_content
                logging.info(f"Successfully loaded target document: {len(content)} characters")
                logging.info(f"Content preview: {content[:200]}")
                
                # Check if content contains relevant keywords
                keywords = ["network", "access", "control", "block", "firewall"]
                found_keywords = [kw for kw in keywords if kw.lower() in content.lower()]
                logging.info(f"Keywords found in target document: {found_keywords}")
                
                return True
            else:
                logging.error("Target document loaded but no content extracted")
                return False
                
        except Exception as e:
            logging.error(f"Error loading target document: {e}")
            return False

    def load_documents_from_folder(self) -> List:
        """Enhanced document loading with specific verification for target document"""
        documents = []
        pdf_loaded = False
        target_doc_loaded = False
        
        if not os.path.exists(self.pdf_directory):
            logging.warning(f"Folder does not exist: {self.pdf_directory}")
            return documents
            
        # First, verify our target document can be loaded
        self.verify_specific_document_loading()
        
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
                    logging.info(f"Loaded PDF documents from {self.pdf_directory}")
                elif ext in [".doc", ".docx"]:
                    loader = UnstructuredWordDocumentLoader(fpath)
                    doc_content = loader.load()
                    
                    # Special handling for our target document
                    if "GDnR_Blocking_Network_Access_Control" in fname:
                        if doc_content:
                            target_doc_loaded = True
                            logging.info(f"✅ Successfully loaded TARGET document: {fname}")
                            logging.info(f"Target document content length: {len(doc_content[0].page_content) if doc_content else 0}")
                        else:
                            logging.error(f"❌ TARGET document loaded but no content: {fname}")
                            
                    documents.extend(doc_content)
                    logging.info(f"Loaded Word document: {fname}")
                elif ext in [".xlsx", ".xls"]:
                    loader = UnstructuredExcelLoader(fpath)
                    doc_content = loader.load()
                    
                    # Special handling for contacts Excel file
                    if "contact" in fname.lower() or "escalation" in fname.lower():
                        if doc_content:
                            logging.info(f"✅ Successfully loaded CONTACTS Excel file: {fname}")
                            logging.info(f"Excel content length: {len(doc_content[0].page_content) if doc_content else 0}")
                            # Log a preview of the content
                            if doc_content and doc_content[0].page_content:
                                preview = doc_content[0].page_content[:500]
                                logging.info(f"Excel content preview: {preview}...")
                        else:
                            logging.error(f"❌ CONTACTS Excel file loaded but no content: {fname}")
                    
                    documents.extend(doc_content)
                    logging.info(f"Loaded Excel document: {fname}")
            except Exception as e:
                logging.error(f"Failed to load {fname}: {e}")
                if "GDnR_Blocking_Network_Access_Control" in fname:
                    logging.error(f"❌ CRITICAL: Failed to load TARGET document: {fname}")
                    
        # Log final status
        if target_doc_loaded:
            logging.info("✅ TARGET document successfully loaded and will be indexed")
        else:
            logging.error("❌ TARGET document was NOT loaded - this explains why it's not found in searches")
            
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
        logging.info(f"Split into {len(texts)} text chunks with improved chunking strategy.")
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
            
        logging.info(f"Loading documents from: {self.pdf_directory}")
        documents = self.load_documents_from_folder()
        
        if not documents:
            logging.warning(f"No documents could be loaded from '{self.pdf_directory}'. Skipping vector store build.")
            return False
            
        logging.info(f"Loaded {len(documents)} documents.")
        
        # Create text chunks
        texts = self.create_text_chunks(documents)
        
        # Create vector store
        logging.info("Creating vector store with FAISS and Ollama embeddings...")
        try:
            self.vector_store = FAISS.from_documents(texts, embeddings)
            
            # Save the vector store
            os.makedirs(os.path.dirname(self.faiss_index_path), exist_ok=True)
            self.vector_store.save_local(self.faiss_index_path)
            logging.info(f"Vector store saved to: {self.faiss_index_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error creating or saving vector store: {e}", exc_info=True)
            return False

    def load_vector_store(self, embeddings) -> bool:
        """Load existing vector store from disk"""
        try:
            logging.info(f"Loading existing FAISS index from: {self.faiss_index_path}")
            self.vector_store = FAISS.load_local(
                self.faiss_index_path,
                embeddings,
                allow_dangerous_deserialization=True
            )
            logging.info("FAISS index loaded successfully.")
            return True
        except Exception as e:
            logging.error(f"Error loading FAISS index: {e}", exc_info=True)
            return False

    def initialize_vector_store(self, embeddings) -> bool:
        """Initialize vector store - load existing or build new, auto-rebuild if docs changed"""
        # Check if we need to rebuild due to new/changed documents
        if os.path.exists(self.faiss_index_path):
            if self._should_rebuild_index():
                logging.info("🔄 New or changed documents detected, rebuilding vector store...")
                if self.build_and_save_vector_store(embeddings):
                    return self.load_vector_store(embeddings)
                else:
                    logging.error("Failed to rebuild, attempting to load existing index...")
            
            if self.load_vector_store(embeddings):
                return True
            else:
                logging.info("Failed to load existing vector store, rebuilding...")
                if self.build_and_save_vector_store(embeddings):
                    return self.load_vector_store(embeddings)
        else:
            logging.info(f"FAISS index not found at {self.faiss_index_path}. Building new vector store.")
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
            if file.endswith(('.pdf', '.docx')):
                file_path = os.path.join(self.pdf_directory, file)
                if os.path.getmtime(file_path) > index_mtime:
                    logging.info(f"📄 Newer document found: {file}")
                    return True
        
        return False

    def create_retriever(self):
        """Create retriever from vector store"""
        if not self.vector_store:
            logging.error("Vector store not initialized")
            return None
            
        self.retriever = self.vector_store.as_retriever(search_kwargs={"k": self.retrieval_k})
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
            Returns detailed content from relevant documents with clear source references.
            """
            try:
                docs = self.retriever.get_relevant_documents(query)
                if not docs:
                    return f"No relevant documents found for query: '{query}'"
                
                # Group results by source document
                sources_content = {}
                for doc in docs:
                    source_file = os.path.basename(doc.metadata.get('source', 'Unknown document'))
                    if source_file not in sources_content:
                        sources_content[source_file] = []
                    sources_content[source_file].append(doc.page_content.strip())
                
                # Build response with source attribution
                response_parts = []
                
                for source_file, contents in sources_content.items():
                    # Combine content from same source
                    combined_content = "\n\n".join(contents[:2])  # Limit to top 2 chunks per source
                    response_parts.append(f"📄 **From {source_file}:**\n{combined_content}")
                
                # Join all sources
                result = "\n\n" + "\n\n".join(response_parts)
                
                # Add source summary at the end
                source_list = list(sources_content.keys())
                if len(source_list) == 1:
                    result += f"\n\n**Source:** {source_list[0]}"
                else:
                    result += f"\n\n**Sources:** {', '.join(source_list[:3])}"
                    if len(source_list) > 3:
                        result += f" and {len(source_list) - 3} other documents"
                
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
            docs = self.retriever.get_relevant_documents(query)
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
        logging.info("Force rebuilding vector store...")
        
        # Remove existing index if it exists
        if os.path.exists(self.faiss_index_path):
            try:
                import shutil
                shutil.rmtree(self.faiss_index_path)
                logging.info("Removed existing FAISS index")
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
            
        logging.info(f"Updated retrieval settings: k={self.retrieval_k}, chunk_size={self.chunk_size}, chunk_overlap={self.chunk_overlap}")