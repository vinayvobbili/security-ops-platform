# /services/enhanced_config.py
"""
Enhanced Configuration Module

This module provides enhanced configuration management with environment variable
support, validation, and configuration file loading capabilities.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

# Import the centralized config system
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
import my_config

# Get the config instance
_main_config = my_config.get_config()

@dataclass
class ModelConfig:
    """Configuration for AI models"""
    llm_model_name: str = _main_config.ollama_llm_model
    embedding_model_name: str = _main_config.ollama_embedding_model
    temperature: float = 0.1
    max_iterations: int = 3  # Keep it tight - forces smarter tool usage
    chunk_size: int = 1500
    chunk_overlap: int = 300
    retrieval_k: int = 5


@dataclass
class PathConfig:
    """Configuration for file paths"""
    base_dir: str = field(default_factory=lambda: os.path.dirname(os.path.dirname(__file__)))
    pdf_directory: str = field(init=False)
    chroma_documents_path: str = field(init=False)
    performance_data_path: str = field(init=False)
    logs_directory: str = field(init=False)

    def __post_init__(self):
        self.pdf_directory = os.path.join(self.base_dir, "local_pdfs_docs")
        self.chroma_documents_path = os.path.join(self.base_dir, "chroma_documents")
        self.logs_directory = os.path.join(self.base_dir, "logs")


@dataclass
class SessionConfig:
    """Configuration for session management"""
    session_timeout_hours: int = 24
    max_interactions_per_user: int = 10
    cleanup_interval_hours: int = 1


@dataclass
class PerformanceConfig:
    """Configuration for performance monitoring"""
    max_response_time_samples: int = 1000
    save_interval_requests: int = 10
    concurrent_user_warning_threshold: int = 50
    memory_warning_threshold: float = 85.0
    response_time_warning_threshold: float = 10.0
    error_count_warning_threshold: int = 10


@dataclass
class SecurityConfig:
    """Configuration for security settings"""
    max_input_length: int = 5000
    max_response_length: int = 7400
    enable_input_sanitization: bool = True
    log_user_queries: bool = True
    log_responses: bool = True


@dataclass
class APIConfig:
    """Configuration for external APIs"""
    openweather_api_key: str = ""
    openweather_base_url: str = "http://api.openweathermap.org/data/2.5/weather"
    openweather_timeout: int = 10
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_base_url: str = ""


@dataclass
class EnhancedConfig:
    """Enhanced configuration container"""
    model: ModelConfig = field(default_factory=ModelConfig)
    paths: PathConfig = field(default_factory=PathConfig)
    session: SessionConfig = field(default_factory=SessionConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    api: APIConfig = field(default_factory=APIConfig)

    # Legacy compatibility
    open_weather_map_api_key: str = field(init=False)

    def __post_init__(self):
        # Legacy compatibility
        self.open_weather_map_api_key = self.api.openweather_api_key


class ConfigManager:
    """Enhanced configuration manager with environment variable support"""

    def __init__(self, config_file: str = None):
        self.config_file = config_file or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config", "bot_config.json"
        )
        self._config: Optional[EnhancedConfig] = None

    def load_config(self) -> EnhancedConfig:
        """Load configuration from file and environment variables"""
        if self._config is not None:
            return self._config

        # Start with default config
        config_dict = {}

        # Load from file if it exists
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    file_config = json.load(f)
                    config_dict.update(file_config)
                    logging.info(f"Loaded configuration from {self.config_file}")
            except Exception as e:
                logging.warning(f"Failed to load config file {self.config_file}: {e}")

        # Override with environment variables
        env_overrides = self._load_from_environment()
        config_dict.update(env_overrides)

        # Create config objects
        self._config = self._create_config_from_dict(config_dict)

        # Validate configuration
        self._validate_config()

        return self._config

    @staticmethod
    def _load_from_environment() -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}

        # Model configuration
        if os.getenv('OLLAMA_LLM_MODEL'):
            env_config.setdefault('model', {})['llm_model_name'] = os.getenv('OLLAMA_LLM_MODEL')
        if os.getenv('OLLAMA_EMBEDDING_MODEL'):
            env_config.setdefault('model', {})['embedding_model_name'] = os.getenv('OLLAMA_EMBEDDING_MODEL')
        if os.getenv('MODEL_TEMPERATURE'):
            env_config.setdefault('model', {})['temperature'] = float(os.getenv('MODEL_TEMPERATURE'))

        # Path configuration
        if os.getenv('PDF_DIRECTORY'):
            env_config.setdefault('paths', {})['pdf_directory'] = os.getenv('PDF_DIRECTORY')
        if os.getenv('CHROMA_DOCUMENTS_PATH'):
            env_config.setdefault('paths', {})['chroma_documents_path'] = os.getenv('CHROMA_DOCUMENTS_PATH')
        if os.getenv('LOGS_DIRECTORY'):
            env_config.setdefault('paths', {})['logs_directory'] = os.getenv('LOGS_DIRECTORY')

        # Session configuration
        if os.getenv('SESSION_TIMEOUT_HOURS'):
            env_config.setdefault('session', {})['session_timeout_hours'] = int(os.getenv('SESSION_TIMEOUT_HOURS'))
        if os.getenv('MAX_INTERACTIONS_PER_USER'):
            env_config.setdefault('session', {})['max_interactions_per_user'] = int(os.getenv('MAX_INTERACTIONS_PER_USER'))

        # Performance configuration
        if os.getenv('MAX_RESPONSE_TIME_SAMPLES'):
            env_config.setdefault('performance', {})['max_response_time_samples'] = int(os.getenv('MAX_RESPONSE_TIME_SAMPLES'))
        if os.getenv('CONCURRENT_USER_WARNING_THRESHOLD'):
            env_config.setdefault('performance', {})['concurrent_user_warning_threshold'] = int(os.getenv('CONCURRENT_USER_WARNING_THRESHOLD'))

        # Security configuration
        if os.getenv('MAX_INPUT_LENGTH'):
            env_config.setdefault('security', {})['max_input_length'] = int(os.getenv('MAX_INPUT_LENGTH'))
        if os.getenv('ENABLE_INPUT_SANITIZATION'):
            env_config.setdefault('security', {})['enable_input_sanitization'] = os.getenv('ENABLE_INPUT_SANITIZATION').lower() == 'true'

        # API configuration
        if os.getenv('OPENWEATHER_API_KEY'):
            env_config.setdefault('api', {})['openweather_api_key'] = os.getenv('OPENWEATHER_API_KEY')
        if os.getenv('CROWDSTRIKE_CLIENT_ID'):
            env_config.setdefault('api', {})['crowdstrike_client_id'] = os.getenv('CROWDSTRIKE_CLIENT_ID')
        if os.getenv('CROWDSTRIKE_CLIENT_SECRET'):
            env_config.setdefault('api', {})['crowdstrike_client_secret'] = os.getenv('CROWDSTRIKE_CLIENT_SECRET')
        if os.getenv('CROWDSTRIKE_BASE_URL'):
            env_config.setdefault('api', {})['crowdstrike_base_url'] = os.getenv('CROWDSTRIKE_BASE_URL')

        return env_config

    @staticmethod
    def _create_config_from_dict(config_dict: Dict[str, Any]) -> EnhancedConfig:
        """Create EnhancedConfig from dictionary"""
        # Create individual config objects
        model_config = ModelConfig(**config_dict.get('model', {}))
        paths_config = PathConfig(**config_dict.get('paths', {}))
        session_config = SessionConfig(**config_dict.get('session', {}))
        performance_config = PerformanceConfig(**config_dict.get('performance', {}))
        security_config = SecurityConfig(**config_dict.get('security', {}))
        api_config = APIConfig(**config_dict.get('api', {}))

        return EnhancedConfig(
            model=model_config,
            paths=paths_config,
            session=session_config,
            performance=performance_config,
            security=security_config,
            api=api_config
        )

    def _validate_config(self):
        """Validate configuration values"""
        if not self._config:
            return

        # Validate model configuration
        if self._config.model.temperature < 0 or self._config.model.temperature > 2:
            logging.warning(f"Invalid temperature value: {self._config.model.temperature}, using default")
            self._config.model.temperature = 0.1

        # Validate performance thresholds
        if self._config.performance.concurrent_user_warning_threshold < 1:
            logging.warning("Invalid concurrent user warning threshold, using default")
            self._config.performance.concurrent_user_warning_threshold = 50

        # Validate security settings
        if self._config.security.max_input_length < 100:
            logging.warning("Max input length too small, using minimum value")
            self._config.security.max_input_length = 100

        # Create directories if they don't exist
        self._ensure_directories_exist()

    def _ensure_directories_exist(self):
        """Ensure required directories exist"""
        directories = [
            self._config.paths.pdf_directory,
            self._config.paths.logs_directory,
            self._config.paths.chroma_documents_path
        ]

        for directory in directories:
            if directory and not os.path.exists(directory):
                try:
                    os.makedirs(directory, exist_ok=True)
                    logging.info(f"Created directory: {directory}")
                except OSError as e:
                    logging.error(f"Failed to create directory {directory}: {e}")

    def save_config(self, config: EnhancedConfig = None):
        """Save configuration to file"""
        if config is None:
            config = self._config

        if not config:
            logging.error("No configuration to save")
            return

        try:
            # Convert to dictionary
            config_dict = {
                'model': {
                    'llm_model_name': config.model.llm_model_name,
                    'embedding_model_name': config.model.embedding_model_name,
                    'temperature': config.model.temperature,
                    'max_iterations': config.model.max_iterations,
                    'chunk_size': config.model.chunk_size,
                    'chunk_overlap': config.model.chunk_overlap,
                    'retrieval_k': config.model.retrieval_k
                },
                'session': {
                    'session_timeout_hours': config.session.session_timeout_hours,
                    'max_interactions_per_user': config.session.max_interactions_per_user,
                    'cleanup_interval_hours': config.session.cleanup_interval_hours
                },
                'performance': {
                    'max_response_time_samples': config.performance.max_response_time_samples,
                    'save_interval_requests': config.performance.save_interval_requests,
                    'concurrent_user_warning_threshold': config.performance.concurrent_user_warning_threshold,
                    'memory_warning_threshold': config.performance.memory_warning_threshold,
                    'response_time_warning_threshold': config.performance.response_time_warning_threshold,
                    'error_count_warning_threshold': config.performance.error_count_warning_threshold
                },
                'security': {
                    'max_input_length': config.security.max_input_length,
                    'max_response_length': config.security.max_response_length,
                    'enable_input_sanitization': config.security.enable_input_sanitization,
                    'log_user_queries': config.security.log_user_queries,
                    'log_responses': config.security.log_responses
                },
                'api': {
                    'openweather_api_key': config.api.openweather_api_key,
                    'openweather_base_url': config.api.openweather_base_url,
                    'openweather_timeout': config.api.openweather_timeout,
                    'crowdstrike_client_id': config.api.crowdstrike_client_id,
                    'crowdstrike_client_secret': config.api.crowdstrike_client_secret,
                    'crowdstrike_base_url': config.api.crowdstrike_base_url
                }
            }

            # Ensure config directory exists
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)

            # Save to file
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)

            logging.info(f"Configuration saved to {self.config_file}")

        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")

    def reload_config(self) -> EnhancedConfig:
        """Reload configuration from file and environment"""
        self._config = None
        return self.load_config()

    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for logging/debugging"""
        if not self._config:
            return {}

        return {
            'model': {
                'llm_model': self._config.model.llm_model_name,
                'embedding_model': self._config.model.embedding_model_name,
                'temperature': self._config.model.temperature
            },
            'session': {
                'timeout_hours': self._config.session.session_timeout_hours,
                'max_interactions': self._config.session.max_interactions_per_user
            },
            'security': {
                'max_input_length': self._config.security.max_input_length,
                'input_sanitization': self._config.security.enable_input_sanitization
            },
            'api': {
                'openweather_configured': bool(self._config.api.openweather_api_key),
                'crowdstrike_configured': bool(self._config.api.crowdstrike_client_id)
            }
        }


# Global config manager instance
_config_manager = None


def get_enhanced_config() -> EnhancedConfig:
    """Get enhanced configuration (singleton)"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.load_config()


def reload_enhanced_config() -> EnhancedConfig:
    """Reload enhanced configuration"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.reload_config()


def save_enhanced_config(config: EnhancedConfig):
    """Save enhanced configuration"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    _config_manager.save_config(config)
