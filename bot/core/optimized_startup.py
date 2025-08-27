# /bot/core/optimized_startup.py
"""
Optimized Startup Manager for Pokedex

Implements several performance optimizations:
1. Parallel initialization of components
2. Model pre-loading and keep-alive
3. Fast warmup strategies
4. Background initialization of non-critical components
"""

import os
import logging
import asyncio
import concurrent.futures
import time
from typing import Optional, Tuple, Dict, Any
from threading import Thread

from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain.agents import AgentExecutor

from my_config import get_config
from bot.utils.enhanced_config import ModelConfig
from bot.core.state_manager import SecurityBotStateManager, get_state_manager


class OptimizedStartupManager:
    """Manages optimized startup for faster Pokedex initialization"""
    
    def __init__(self):
        self.config = get_config()
        self.model_config = ModelConfig()
        self.logger = logging.getLogger(__name__)
        
        # State tracking
        self.model_preloaded = False
        self.startup_metrics = {}
        
    def pre_load_model(self) -> bool:
        """Pre-load the LLM model to ensure it's in Ollama's memory"""
        try:
            self.logger.info(f"Pre-loading model {self.model_config.llm_model_name}...")
            start_time = time.time()
            
            # Create a simple LLM instance just to trigger model loading
            temp_llm = ChatOllama(
                model=self.model_config.llm_model_name,
                temperature=0.0,
                timeout=120  # Generous timeout for model loading
            )
            
            # Send a minimal request to force model loading
            response = temp_llm.invoke("ping")
            load_time = time.time() - start_time
            
            if response:
                self.logger.info(f"✅ Model pre-loaded successfully in {load_time:.1f}s")
                self.model_preloaded = True
                self.startup_metrics['model_preload_time'] = load_time
                return True
            else:
                self.logger.warning("Model pre-load returned empty response")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to pre-load model: {e}")
            return False
    
    def parallel_initialize_components(self) -> Tuple[bool, Dict[str, Any]]:
        """Initialize components in parallel for faster startup"""
        start_time = time.time()
        results = {}
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                # Submit initialization tasks in parallel
                futures = {
                    'managers': executor.submit(self._init_managers),
                    'ai_components': executor.submit(self._init_ai_components_optimized),
                    'model_warmup': executor.submit(self._fast_warmup) if self.model_preloaded else None
                }
                
                # Collect results
                for task_name, future in futures.items():
                    if future:
                        try:
                            result = future.result(timeout=60)  # 60 second timeout per task
                            results[task_name] = result
                        except Exception as e:
                            self.logger.error(f"Task {task_name} failed: {e}")
                            results[task_name] = False
            
            # Initialize document processing in background (non-blocking)
            self._background_init_documents()
            
            total_time = time.time() - start_time
            self.startup_metrics['parallel_init_time'] = total_time
            
            success = all(results.values())
            self.logger.info(f"Parallel initialization completed in {total_time:.1f}s - Success: {success}")
            return success, results
            
        except Exception as e:
            self.logger.error(f"Parallel initialization failed: {e}")
            return False, results
    
    def _init_managers(self) -> bool:
        """Initialize core managers"""
        try:
            state_manager = get_state_manager()
            state_manager._initialize_managers()
            return True
        except Exception as e:
            self.logger.error(f"Manager initialization failed: {e}")
            return False
    
    def _init_ai_components_optimized(self) -> bool:
        """Initialize AI components with optimization for pre-loaded models"""
        try:
            state_manager = get_state_manager()
            
            # If model is pre-loaded, initialization should be much faster
            if self.model_preloaded:
                self.logger.info("Using pre-loaded model for faster initialization")
            
            return state_manager._initialize_ai_components()
            
        except Exception as e:
            self.logger.error(f"AI component initialization failed: {e}")
            return False
    
    def _fast_warmup(self) -> bool:
        """Fast warmup using pre-loaded model"""
        try:
            if not self.model_preloaded:
                return False
                
            self.logger.info("Performing fast warmup...")
            start_time = time.time()
            
            # Use direct LLM call instead of full agent for faster warmup
            state_manager = get_state_manager()
            if state_manager.llm:
                response = state_manager.llm.invoke("Hello")
                warmup_time = time.time() - start_time
                self.startup_metrics['warmup_time'] = warmup_time
                
                if response:
                    self.logger.info(f"✅ Fast warmup completed in {warmup_time:.1f}s")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Fast warmup failed: {e}")
            return False
    
    def _background_init_documents(self):
        """Initialize document processing in background thread"""
        def init_documents():
            try:
                self.logger.info("Starting background document initialization...")
                state_manager = get_state_manager()
                
                if state_manager._initialize_document_processing():
                    self.logger.info("✅ Background document initialization completed")
                    
                    # Initialize agent now that documents are ready
                    if state_manager._initialize_agent():
                        state_manager.is_initialized = True
                        self.logger.info("✅ Full bot initialization completed with RAG")
                    else:
                        self.logger.warning("Agent initialization failed after document processing")
                else:
                    self.logger.warning("Document processing initialization failed - continuing without RAG")
                    
                    # Initialize agent without RAG
                    if state_manager._initialize_agent():
                        state_manager.is_initialized = True
                        self.logger.info("✅ Bot initialization completed without RAG")
                        
            except Exception as e:
                self.logger.error(f"Background document initialization failed: {e}")
        
        # Start background thread
        bg_thread = Thread(target=init_documents, daemon=True)
        bg_thread.start()
    
    def optimized_full_startup(self) -> Tuple[bool, float]:
        """Complete optimized startup sequence"""
        total_start_time = time.time()
        
        try:
            self.logger.info("🚀 Starting optimized Pokedex initialization...")
            
            # Step 1: Pre-load model (most time-consuming)
            self.logger.info("Step 1: Pre-loading LLM model...")
            model_preload_success = self.pre_load_model()
            
            # Step 2: Parallel initialization of other components
            self.logger.info("Step 2: Parallel component initialization...")
            parallel_success, results = self.parallel_initialize_components()
            
            total_time = time.time() - total_start_time
            self.startup_metrics['total_startup_time'] = total_time
            
            overall_success = model_preload_success and parallel_success
            
            if overall_success:
                self.logger.info(f"✅ Optimized startup completed successfully in {total_time:.1f}s")
                self._log_startup_metrics()
            else:
                self.logger.error(f"❌ Optimized startup completed with issues in {total_time:.1f}s")
                self._log_startup_metrics()
            
            return overall_success, total_time
            
        except Exception as e:
            total_time = time.time() - total_start_time
            self.logger.error(f"Optimized startup failed after {total_time:.1f}s: {e}")
            return False, total_time
    
    def _log_startup_metrics(self):
        """Log detailed startup metrics for analysis"""
        self.logger.info("🔍 Startup Performance Metrics:")
        for metric, value in self.startup_metrics.items():
            self.logger.info(f"  {metric}: {value:.2f}s")


def ensure_model_availability() -> bool:
    """Ensure the required model is available in Ollama"""
    import subprocess
    
    try:
        config = get_config()
        model_config = ModelConfig()
        
        logging.info(f"Checking model availability: {model_config.llm_model_name}")
        
        # Check if model is already loaded
        result = subprocess.run(['ollama', 'ps'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and model_config.llm_model_name in result.stdout:
            logging.info(f"✅ Model {model_config.llm_model_name} is already loaded")
            return True
        
        # Check if model is available locally
        result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and model_config.llm_model_name in result.stdout:
            logging.info(f"✅ Model {model_config.llm_model_name} is available locally")
            return True
        else:
            logging.error(f"❌ Model {model_config.llm_model_name} not found. Please run: ollama pull {model_config.llm_model_name}")
            return False
            
    except subprocess.TimeoutExpired:
        logging.error("Timeout checking ollama models")
        return False
    except Exception as e:
        logging.error(f"Error checking model availability: {e}")
        return False


def keep_model_alive():
    """Keep the model alive in Ollama to prevent unloading"""
    def keep_alive_worker():
        try:
            model_config = ModelConfig()
            llm = ChatOllama(model=model_config.llm_model_name, temperature=0.0)
            
            while True:
                try:
                    # Send a minimal ping every 4 minutes to keep model loaded
                    # (Ollama default timeout is 5 minutes)
                    time.sleep(240)  # 4 minutes
                    llm.invoke("ping")
                    logging.debug(f"Keep-alive ping sent to {model_config.llm_model_name}")
                except Exception as e:
                    logging.warning(f"Keep-alive ping failed: {e}")
                    
        except Exception as e:
            logging.error(f"Keep-alive worker failed: {e}")
    
    # Start keep-alive in background thread
    keep_alive_thread = Thread(target=keep_alive_worker, daemon=True)
    keep_alive_thread.start()
    logging.info("🔄 Keep-alive worker started for model persistence")


# Global instance
_startup_manager = None

def get_startup_manager() -> OptimizedStartupManager:
    """Get global startup manager instance"""
    global _startup_manager
    if _startup_manager is None:
        _startup_manager = OptimizedStartupManager()
    return _startup_manager