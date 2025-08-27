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
from langchain.agents import AgentExecutor, create_react_agent
from langchain_core.prompts import ChatPromptTemplate

from my_config import get_config
from bot.utils.enhanced_config import ModelConfig
from bot.monitoring.performance_monitor import PerformanceMonitor
from bot.monitoring.session_manager import SessionManager
from bot.document.document_processor import DocumentProcessor
from bot.tools.crowdstrike_tools import CrowdStrikeToolsManager
from bot.tools.weather_tools import WeatherToolsManager


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
        self.performance_monitor: Optional[PerformanceMonitor] = None
        self.session_manager: Optional[SessionManager] = None
        self.document_processor: Optional[DocumentProcessor] = None
        self.crowdstrike_manager: Optional[CrowdStrikeToolsManager] = None
        self.weather_manager: Optional[WeatherToolsManager] = None
        
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
        self.performance_data_path = os.path.join(project_root, "performance_data.json")
    
    
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
        # Performance monitoring
        self.performance_monitor = PerformanceMonitor(
            max_response_time_samples=1000,
            data_file_path=self.performance_data_path
        )
        
        # Session management
        self.session_manager = SessionManager(
            session_timeout_hours=24,
            max_interactions_per_user=10
        )
        
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
        self.weather_manager = WeatherToolsManager(
            api_key=self.config.open_weather_map_api_key
        )
        
        logging.info("Core managers initialized")
    
    def _initialize_ai_components(self) -> bool:
        """Initialize AI components (LLM and embeddings)"""
        try:
            logging.info(f"Initializing Langchain model: {self.model_config.llm_model_name}...")
            self.llm = ChatOllama(
                model=self.model_config.llm_model_name, 
                temperature=self.model_config.temperature,
                timeout=300  # Very generous timeout for large models
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
            all_tools.extend(self.weather_manager.get_tools())
            
            # Add CrowdStrike tools if available
            if self.crowdstrike_manager.is_available():
                all_tools.extend(self.crowdstrike_manager.get_tools())
                logging.info("CrowdStrike tools added to agent.")
            
            # Add RAG tool if available
            if self.document_processor.retriever:
                rag_tool = self.document_processor.create_rag_tool()
                if rag_tool:
                    all_tools.append(rag_tool)
                    logging.info("RAG tool (search_local_documents) added to agent tools.")
            
            # Create agent prompt
            prompt_template = self._get_agent_prompt_template()
            prompt = ChatPromptTemplate.from_template(prompt_template)
            
            # Create the ReAct agent
            agent = create_react_agent(self.llm, all_tools, prompt)
            
            # Create agent executor
            self.agent_executor = AgentExecutor(
                agent=agent,
                tools=all_tools,
                verbose=True,
                handle_parsing_errors=True,
                max_iterations=self.model_config.max_iterations,
                return_intermediate_steps=False
            )
            
            logging.info("Langchain Agent Executor initialized successfully with all tools.")
            return True
            
        except Exception as e:
            logging.error(f"Failed to initialize agent: {e}")
            return False
    
    def _get_agent_prompt_template(self) -> str:
        """Get the agent prompt template"""
        return """You are a security operations assistant helping SOC analysts.

ALWAYS search local documents first for ANY question that could be related to security, threats, procedures, or tools. 

For simple greetings or status checks (like "hello", "are you working", "hi"), you can respond directly without using tools.

CRITICAL: When presenting document search results, be smart about relevance:

1. **For SPECIFIC queries** (like "who are contacts for AIX servers"): Extract and present only the relevant information while preserving source attribution format. Present the answer directly without repeating the document name in the body if it appears in the source line:
   
   [Relevant content that answers the question]
   
   **Source:** [document_name]

2. **For GENERAL queries** (like "how to handle incidents"): Include more comprehensive content from the search results.

ALWAYS maintain proper source attribution but focus on what directly answers the user's question. Don't include irrelevant sections from documents.

HYBRID APPROACH: If local documents don't contain relevant information, you may provide general security knowledge from your training data, but you MUST:
- Clearly label it as: "⚠️ **General Security Guidance** (not from local documentation)"
- Provide helpful, accurate security information
- Suggest checking with local security team for organization-specific procedures
- Still prioritize and search documents first

You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do

For simple greetings or status checks, you can skip directly to Final Answer.

For security questions requiring tools:
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

IMPORTANT: For questions requiring tools, after receiving an Observation, you MUST start your next response with either:
- "Thought: " (if you need to do more actions)
- "Final Answer: " (if you have enough information to answer)

Begin!

Question: {input}
Thought:{agent_scratchpad}"""
    
    def _shutdown_handler(self):
        """Handle graceful shutdown"""
        try:
            if self.performance_monitor:
                self.performance_monitor.save_data()
            
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
    
    def get_performance_monitor(self) -> Optional[PerformanceMonitor]:
        """Get performance monitor instance"""
        return self.performance_monitor
    
    def get_session_manager(self) -> Optional[SessionManager]:
        """Get session manager instance"""
        return self.session_manager
    
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
        
        if self.performance_monitor:
            self.performance_monitor.reset_stats()
        
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


def initialize_security_bot() -> bool:
    """Initialize the security bot (convenience function)"""
    state_manager = get_state_manager()
    return state_manager.initialize_all_components()