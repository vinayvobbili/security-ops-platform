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
import re
from typing import Optional

from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain.agents import AgentExecutor

from my_config import get_config
from pokedex_bot.utils.enhanced_config import ModelConfig
from pokedex_bot.document.document_processor import DocumentProcessor
from pokedex_bot.tools.crowdstrike_tools import CrowdStrikeToolsManager
from pokedex_bot.tools.weather_tools import get_weather_info_tool
# Skip staffing tools import due to missing webexpythonsdk dependency
# from pokedex_bot.tools.staffing_tools import StaffingToolsManager
from pokedex_bot.tools.metrics_tools import MetricsToolsManager
from pokedex_bot.tools.test_tools import TestToolsManager
from pokedex_bot.tools.network_monitoring_tools import NetworkMonitoringToolsManager


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
        self.agent_executor: Optional[AgentExecutor] = None

        # Managers
        self.document_processor: Optional[DocumentProcessor] = None
        self.crowdstrike_manager: Optional[CrowdStrikeToolsManager] = None
        self.weather_tool = None
        self.staffing_manager: Optional[StaffingToolsManager] = None
        self.metrics_manager: Optional[MetricsToolsManager] = None
        self.test_manager: Optional[TestToolsManager] = None

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

        # Tool managers
        self.crowdstrike_manager = CrowdStrikeToolsManager()
        self.weather_tool = get_weather_info_tool(
            api_key=self.config.open_weather_map_api_key
        )
        # Skip staffing tools due to missing webexpythonsdk dependency
        self.staffing_manager = None
        self.metrics_manager = MetricsToolsManager()
        self.test_manager = TestToolsManager()

        logging.info("Core managers initialized")

    def _initialize_ai_components(self) -> bool:
        """Initialize AI components (LLM and embeddings)"""
        try:
            logging.info(f"Initializing Langchain model: {self.model_config.llm_model_name}...")
            self.llm = ChatOllama(
                model=self.model_config.llm_model_name,
                temperature=self.model_config.temperature
            )
            logging.info(f"Langchain model {self.model_config.llm_model_name} initialized.")

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
            all_tools = []

            # Add weather tools
            all_tools.append(self.weather_tool)

            # Add CrowdStrike tools if available
            if self.crowdstrike_manager.is_available():
                all_tools.extend(self.crowdstrike_manager.get_tools())
                logging.info("CrowdStrike tools added to agent.")

            # Add staffing tools (skip if not available)
            if self.staffing_manager and self.staffing_manager.is_available():
                all_tools.extend(self.staffing_manager.get_tools())
                logging.info("Staffing tools added to agent.")

            # Add metrics tools
            if self.metrics_manager.is_available():
                all_tools.extend(self.metrics_manager.get_tools())
                logging.info("Metrics tools added to agent.")

            # Add test tools
            if self.test_manager.is_available():
                all_tools.extend(self.test_manager.get_tools())
                logging.info("Test execution tools added to agent.")

            # Add RAG tool if available
            if self.document_processor.retriever:
                rag_tool = self.document_processor.create_rag_tool()
                if rag_tool:
                    all_tools.append(rag_tool)
                    logging.info("RAG tool (search_local_documents) added to agent tools.")

            # No complex agent framework needed - using direct LLM calls

            # Skip the agent framework entirely - direct LLM with tool calling logic
            self.agent_executor = None  # We'll handle this manually
            self.llm_with_tools = self.llm
            self.available_tools = {tool.name: tool for tool in all_tools}

            logging.info("Direct LLM with tools initialized successfully.")
            return True

        except Exception as e:
            logging.error(f"Failed to initialize agent: {e}")
            return False

    def execute_query(self, query: str) -> str:
        """Execute query directly with the 70B model - no agent framework"""
        try:
            # Simple prompt for the LLM
            tool_names = list(self.available_tools.keys())
            prompt = f"""You are a security operations assistant.

Available tools: {', '.join(tool_names)}

To use a tool:
Action: tool_name
Action Input: parameter

User query: {query}

Response:"""

            # Get LLM response
            response = self.llm_with_tools.invoke(prompt)
            
            # Check if the LLM wants to use a tool
            if "Action:" in response.content:
                # Extract and execute tool call
                action_match = re.search(r"Action:\s*(\w+)", response.content)
                input_match = re.search(r"Action Input:\s*(.+)", response.content)
                
                if action_match and input_match:
                    tool_name = action_match.group(1)
                    tool_input = input_match.group(1).strip()
                    
                    if tool_name in self.available_tools:
                        tool_result = self.available_tools[tool_name].run(tool_input)
                        
                        # Send tool result back to LLM for final response
                        final_prompt = f"""You are a security operations assistant. 

The user asked: {query}

You used the tool '{tool_name}' and got this result:
{tool_result}

Please provide a clear, helpful response to the user based on this information. Do not show the action format or tool name, just give a natural response."""

                        final_response = self.llm_with_tools.invoke(final_prompt)
                        return final_response.content
            
            # Return direct response
            return response.content
            
        except Exception as e:
            return f"Error: {str(e)}"


    def _shutdown_handler(self):
        """Handle graceful shutdown"""
        try:
            # Clear references to force cleanup
            self.llm = None
            self.embeddings = None
            self.agent_executor = None

        except Exception as e:
            logging.error(f"Error during shutdown: {e}")

    # Component access methods
    def get_llm(self) -> Optional[ChatOllama]:
        """Get LLM instance"""
        return self.llm

    def get_embeddings(self) -> Optional[OllamaEmbeddings]:
        """Get embeddings instance"""
        return self.embeddings

    def get_agent_executor(self) -> Optional[AgentExecutor]:
        """Get agent executor instance"""
        return self.agent_executor

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
            'agent': self.agent_executor is not None,
            'rag': self.document_processor.retriever is not None if self.document_processor else False,
            'crowdstrike': self.crowdstrike_manager.is_available() if self.crowdstrike_manager else False
        }

        return {
            "status": "initialized" if all(component_status.values()) else "partial",
            "components": component_status
        }

    def warmup(self) -> bool:
        """Warm up the model with a simple query"""
        if not self.is_initialized or not self.agent_executor:
            return False

        try:
            logging.info("Warming up the model...")
            result = self.agent_executor.invoke({"input": "Hello, are you working?"})
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
        """Fast warmup using direct LLM call instead of full agent"""
        if not self.llm:
            return False

        try:
            logging.info("Performing fast warmup...")
            response = self.llm.invoke("Hello")
            if response:
                logging.info("Fast warmup completed successfully")
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
        self.agent_executor = None

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
