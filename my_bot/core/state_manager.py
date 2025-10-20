# /services/state_manager.py
"""
State Manager Module

This module provides centralized state management for the security operations bot,
minimizing global variables and providing a clean interface for component access.
"""

import os
import logging
import atexit
import signal
from typing import Optional

from langchain_ollama import ChatOllama, OllamaEmbeddings

from my_config import get_config
from my_bot.utils.enhanced_config import ModelConfig
from my_bot.document.document_processor import DocumentProcessor
from my_bot.tools.crowdstrike_tools import get_device_containment_status, get_device_online_status, get_device_details_cs
from my_bot.tools.weather_tools import get_weather_info
from my_bot.tools.staffing_tools import get_current_shift_info, get_current_staffing
from my_bot.tools.metrics_tools import get_bot_metrics, get_bot_metrics_summary
from my_bot.tools.test_tools import run_tests, simple_live_message_test
from my_bot.tools.network_monitoring_tools import get_network_activity, get_network_summary_tool


class SecurityBotStateManager:
    """Centralized state management for the security operations bot"""

    def __init__(self):
        # Configuration
        self.config = get_config()
        self.model_config = ModelConfig()
        self._setup_paths()

        # Core components
        self.llm: Optional[ChatOllama] = None
        self.embeddings: Optional[OllamaEmbeddings] = None

        # Components
        self.document_processor: Optional[DocumentProcessor] = None

        # Initialization state
        self.is_initialized = False

        # Setup shutdown handlers
        self._setup_shutdown_handlers()

    def _setup_paths(self):
        """Setup file paths configuration"""
        # Go up to project root (bot -> IR)
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        self.pdf_directory_path = os.path.join(project_root, "local_pdfs_docs")
        self.faiss_index_path = os.path.join(project_root, "faiss_index_ollama")

    def _setup_shutdown_handlers(self):
        """Setup graceful shutdown handlers"""
        atexit.register(self._shutdown_handler)
        try:
            signal.signal(signal.SIGTERM, lambda signum, frame: self._shutdown_handler())
            signal.signal(signal.SIGINT, lambda signum, frame: self._shutdown_handler())
        except ValueError:
            # Signal handlers can only be registered in main thread
            # This is expected when running in background threads
            pass

    def initialize_all_components(self) -> bool:
        """Initialize all components in correct order"""
        try:
            logging.info("Starting SecurityBot initialization...")

            # Initialize core managers first
            self._initialize_managers()

            # Initialize AI components
            if not self._initialize_ai_components():
                return False

            # Initialize document processing
            if not self._initialize_document_processing():
                logging.warning("Document processing initialization failed, continuing without RAG")

            # Initialize agent with all tools
            if not self._initialize_agent():
                return False

            self.is_initialized = True
            logging.info("SecurityBot initialization completed successfully")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize SecurityBot: {e}", exc_info=True)
            return False

    def _initialize_managers(self):
        """Initialize core managers"""

        # Document processor
        self.document_processor = DocumentProcessor(
            pdf_directory=self.pdf_directory_path,
            faiss_index_path=self.faiss_index_path
        )
        # Set document processor config from centralized config
        self.document_processor.chunk_size = self.model_config.chunk_size
        self.document_processor.chunk_overlap = self.model_config.chunk_overlap
        self.document_processor.retrieval_k = self.model_config.retrieval_k

        logging.info("Document processor initialized")

    def _initialize_ai_components(self) -> bool:
        """Initialize AI components (LLM and embeddings)"""
        try:
            logging.info(f"Initializing Langchain model: {self.model_config.llm_model_name}...")
            self.llm = ChatOllama(
                model=self.model_config.llm_model_name,
                temperature=self.model_config.temperature,
                keep_alive=-1  # Keep model loaded indefinitely in Ollama memory
            )
            logging.info(f"Langchain model {self.model_config.llm_model_name} initialized with persistent loading.")

            logging.info(f"Initializing Ollama embeddings with model: {self.model_config.embedding_model_name}...")
            self.embeddings = OllamaEmbeddings(
                model=self.model_config.embedding_model_name
                # OllamaEmbeddings doesn't support timeout parameter
            )
            logging.info("Ollama embeddings initialized.")

            return True

        except Exception as e:
            logging.error(f"Failed to initialize AI components: {e}")
            return False

    def _initialize_document_processing(self) -> bool:
        """Initialize document processing and RAG"""
        try:
            # Ensure PDF directory exists
            if not os.path.exists(self.pdf_directory_path):
                os.makedirs(self.pdf_directory_path)
                logging.info(f"Created PDF directory for RAG: {self.pdf_directory_path}")

            # Initialize vector store
            if self.document_processor.initialize_vector_store(self.embeddings):
                self.document_processor.create_retriever()
                logging.info("Document processing initialized successfully")
                return True
            else:
                logging.warning("Document processing initialization failed")
                return False

        except Exception as e:
            logging.error(f"Error initializing document processing: {e}")
            return False

    def _initialize_agent(self) -> bool:
        """Initialize the LangChain agent with all tools"""
        try:
            # Collect all available tools
            all_tools = [
                # Weather tools
                get_weather_info,
                
                # CrowdStrike tools
                get_device_containment_status,
                get_device_online_status, 
                get_device_details_cs,
                
                # Staffing tools
                get_current_shift_info,
                get_current_staffing,
                
                # Metrics tools
                get_bot_metrics,
                get_bot_metrics_summary,
                
                # Network monitoring tools
                get_network_activity,
                get_network_summary_tool,
                
                # Test tools
                run_tests,
                simple_live_message_test
            ]

            # Add RAG tool if available
            if self.document_processor.retriever:
                rag_tool = self.document_processor.create_rag_tool()
                if rag_tool:
                    all_tools.append(rag_tool)
                    logging.info("RAG tool (search_local_documents) added to agent tools.")

            # No complex agent framework needed - using direct LLM calls

            # Use native tool calling
            self.llm_with_tools = self.llm.bind_tools(all_tools)
            self.available_tools = {tool.name: tool for tool in all_tools}

            logging.info("Direct LLM with tools initialized successfully.")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize agent: {e}")
            return False


    def execute_query(self, query: str) -> str:
        """Execute query using native tool calling"""
        try:
            messages = [
                {"role": "system", "content": "You are a security operations assistant. Your responses will be sent as Webex messages, so you can use Webex markdown formatting."},
                {"role": "user", "content": query}
            ]

            # Get initial response (may contain tool calls)
            response = self.llm_with_tools.invoke(messages)

            # If there are tool calls, execute them and get final response
            if hasattr(response, 'tool_calls') and response.tool_calls:
                # Add the AI message with tool calls to conversation
                messages.append({"role": "assistant", "content": response.content})

                # Execute each tool call
                for tool_call in response.tool_calls:
                    tool_name = tool_call['name']
                    tool_args = tool_call.get('args', {})
                    tool_id = tool_call['id']

                    if tool_name in self.available_tools:
                        try:
                            tool_result = self.available_tools[tool_name].invoke(tool_args)
                        except Exception as e:
                            tool_result = f"Error executing {tool_name}: {str(e)}"
                    else:
                        tool_result = f"Tool {tool_name} not found"

                    # Add tool result to conversation
                    messages.append({"role": "tool", "content": str(tool_result), "tool_call_id": tool_id})

                # Get final response with tool results
                final_response = self.llm_with_tools.invoke(messages)
                return final_response.content
            else:
                # No tool calls, return direct response
                return response.content

        except Exception as e:
            return f"Error: {str(e)}"

    def execute_query_stream(self, query: str):
        """Execute query using native tool calling with streaming support

        Yields tokens as they are generated for real-time streaming to clients.
        """
        try:
            messages = [
                {"role": "system", "content": "You are a security operations assistant. Provide clear, helpful responses."},
                {"role": "user", "content": query}
            ]

            # Get initial response (may contain tool calls)
            response = self.llm_with_tools.invoke(messages)

            # If there are tool calls, execute them first then stream final response
            if hasattr(response, 'tool_calls') and response.tool_calls:
                # Add the AI message with tool calls to conversation
                messages.append({"role": "assistant", "content": response.content})

                # Execute each tool call
                for tool_call in response.tool_calls:
                    tool_name = tool_call['name']
                    tool_args = tool_call.get('args', {})
                    tool_id = tool_call['id']

                    if tool_name in self.available_tools:
                        try:
                            tool_result = self.available_tools[tool_name].invoke(tool_args)
                        except Exception as e:
                            tool_result = f"Error executing {tool_name}: {str(e)}"
                    else:
                        tool_result = f"Tool {tool_name} not found"

                    # Add tool result to conversation
                    messages.append({"role": "tool", "content": str(tool_result), "tool_call_id": tool_id})

                # Stream final response with tool results
                for chunk in self.llm_with_tools.stream(messages):
                    if hasattr(chunk, 'content') and chunk.content:
                        yield chunk.content
            else:
                # No tool calls, stream direct response
                for chunk in self.llm_with_tools.stream(messages):
                    if hasattr(chunk, 'content') and chunk.content:
                        yield chunk.content

        except Exception as e:
            yield f"Error: {str(e)}"


    def _shutdown_handler(self):
        """Handle graceful shutdown"""
        try:
            # Clear references to force cleanup
            self.llm = None
            self.embeddings = None
    
        except Exception as e:
            logging.error(f"Error during shutdown: {e}")

    # Component access methods
    def get_llm(self) -> Optional[ChatOllama]:
        """Get LLM instance"""
        return self.llm

    def get_embeddings(self) -> Optional[OllamaEmbeddings]:
        """Get embeddings instance"""
        return self.embeddings


    def get_document_processor(self) -> Optional[DocumentProcessor]:
        """Get document processor instance"""
        return self.document_processor

    # Status and health methods
    def health_check(self) -> dict:
        """Get comprehensive health check"""
        if not self.is_initialized:
            return {"status": "not_initialized", "components": {}}

        component_status = {
            'llm': self.llm is not None,
            'embeddings': self.embeddings is not None,
            'agent': True,  # Always true with native tool calling
            'rag': self.document_processor.retriever is not None if self.document_processor else False
        }

        return {
            "status": "initialized" if all(component_status.values()) else "partial",
            "components": component_status
        }

    def warmup(self) -> bool:
        """Warm up the model with a simple query"""
        if not self.is_initialized or not self.llm_with_tools:
            return False

        try:
            logging.info("Warming up the model...")
            result = self.execute_query("Hello, are you working?")
            if result:
                logging.info("Model warmup completed successfully")
                return True
            else:
                logging.warning("Model warmup returned empty response")
                return False
        except Exception as e:
            logging.error(f"Model warmup failed: {e}")
            return False

    def fast_warmup(self) -> bool:
        """Fast warmup using direct LLM call that keeps model loaded in memory

        Sets keep_alive to a very long duration to ensure the model stays in Ollama's memory
        and doesn't get unloaded after the default 5-minute timeout.
        """
        if not self.llm:
            return False

        try:
            logging.info("Performing fast warmup with persistent model loading...")

            # Use keep_alive=-1 to keep model loaded indefinitely
            # This ensures the model stays in Ollama memory and doesn't get unloaded
            self.llm.keep_alive = -1  # -1 means keep alive indefinitely

            response = self.llm.invoke("Hello")
            if response:
                logging.info("Fast warmup completed successfully - model will stay loaded in memory")
                return True
            else:
                logging.warning("Fast warmup returned empty response")
                return False
        except Exception as e:
            logging.error(f"Fast warmup failed: {e}")
            return False

    def reset_components(self):
        """Reset all components (useful for testing)"""
        logging.info("Resetting all components...")

        self.llm = None
        self.embeddings = None

        self.is_initialized = False
        logging.info("All components reset")


# Global state manager instance
_state_manager = None


def get_state_manager() -> SecurityBotStateManager:
    """Get global state manager instance (singleton)"""
    global _state_manager
    if _state_manager is None:
        _state_manager = SecurityBotStateManager()
    return _state_manager
