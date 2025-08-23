# /services/my_model.py
import os
import logging
import re
import threading
import time
import psutil
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

from typing import Dict, List, Optional

from langchain_ollama import ChatOllama, OllamaEmbeddings
from langchain_core.tools import tool
# --- Agent related imports ---
from langchain.agents import AgentExecutor, create_react_agent  # Modern way to create ReAct agents
from langchain_core.prompts import ChatPromptTemplate
from langchain.tools.retriever import create_retriever_tool  # To wrap RAG as a tool
# ---

# RAG specific imports
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import UnstructuredWordDocumentLoader

from config import get_config
# CrowdStrike integration
from services.crowdstrike import CrowdStrikeClient

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
PDF_DIRECTORY_PATH = os.path.join(os.path.dirname(__file__), "..", "local_pdfs_docs")
FAISS_INDEX_PATH = os.path.join(os.path.dirname(__file__), "..", "faiss_index_ollama")
PERFORMANCE_DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "performance_data.json")
OLLAMA_LLM_MODEL_NAME = "qwen2.5:14b"
OLLAMA_EMBEDDING_MODEL_NAME = "nomic-embed-text"
CONFIG = get_config()

# --- Global Variables ---
llm = None
embeddings_ollama = None
vector_store_retriever = None
agent_executor = None
crowdstrike_client: Optional[CrowdStrikeClient] = None  # CrowdStrike client instance

# Performance monitor and session manager will be initialized after class definitions
performance_monitor = None
session_manager = None


# Thread-safe session management
class SessionManager:
    """Thread-safe session management for multiple users"""

    def __init__(self, session_timeout_hours: int = 24, max_interactions_per_user: int = 10):
        self._sessions: Dict[str, List[Dict]] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        self._session_timeout = timedelta(hours=session_timeout_hours)
        self._max_interactions = max_interactions_per_user
        self._last_cleanup = datetime.now()

    def add_interaction(self, user_id: str, query: str, response: str) -> None:
        """Add a query-response pair to user's session (thread-safe)"""
        with self._lock:
            current_time = datetime.now()

            # Initialize user session if it doesn't exist
            if user_id not in self._sessions:
                self._sessions[user_id] = []

            # Add new interaction
            self._sessions[user_id].append({
                'query': query,
                'response': response,
                'timestamp': current_time.isoformat(),
                'datetime': current_time  # For internal use
            })

            # Trim to max interactions
            if len(self._sessions[user_id]) > self._max_interactions:
                self._sessions[user_id] = self._sessions[user_id][-self._max_interactions:]

            # Periodic cleanup of expired sessions
            if current_time - self._last_cleanup > timedelta(hours=1):
                self._cleanup_expired_sessions()
                self._last_cleanup = current_time

    def get_context(self, user_id: str, limit: int = 3) -> str:
        """Get recent conversation context for a user (thread-safe)"""
        with self._lock:
            if user_id not in self._sessions:
                return ""

            # Filter out expired interactions
            current_time = datetime.now()
            valid_interactions = [
                interaction for interaction in self._sessions[user_id]
                if current_time - interaction['datetime'] < self._session_timeout
            ]

            # Update the session with only valid interactions
            self._sessions[user_id] = valid_interactions

            # Get recent interactions
            recent_interactions = valid_interactions[-limit:]
            context_parts = []

            for interaction in recent_interactions:
                # Truncate long queries/responses for context
                query_snippet = interaction['query'][:100]
                response_snippet = interaction['response'][:100]
                context_parts.append(f"Previous Q: {query_snippet}")
                context_parts.append(f"Previous A: {response_snippet}")

            return "\n".join(context_parts) if context_parts else ""

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions and interactions (called with lock held)"""
        current_time = datetime.now()
        users_to_remove = []

        for user_id, interactions in self._sessions.items():
            # Filter out expired interactions
            valid_interactions = [
                interaction for interaction in interactions
                if current_time - interaction['datetime'] < self._session_timeout
            ]

            if valid_interactions:
                self._sessions[user_id] = valid_interactions
            else:
                users_to_remove.append(user_id)

        # Remove users with no valid interactions
        for user_id in users_to_remove:
            del self._sessions[user_id]

        if users_to_remove:
            logging.info(f"Cleaned up expired sessions for {len(users_to_remove)} users")

    def get_stats(self) -> Dict[str, int]:
        """Get session statistics (thread-safe)"""
        with self._lock:
            current_time = datetime.now()
            active_users = 0
            total_interactions = 0

            for user_id, interactions in self._sessions.items():
                valid_interactions = [
                    interaction for interaction in interactions
                    if current_time - interaction['datetime'] < self._session_timeout
                ]
                if valid_interactions:
                    active_users += 1
                    total_interactions += len(valid_interactions)

            return {
                'active_users': active_users,
                'total_interactions': total_interactions,
                'total_users_ever': len(self._sessions)
            }


# --- Utility Functions ---

def preprocess_message(message: str) -> str:
    """Clean up message formatting (Webex or other chat platforms)"""
    # Remove @mentions
    message = re.sub(r'<@[^>]+>', '', message).strip()

    # Handle common HTML entities
    message = message.replace('&lt;', '<').replace('&gt;', '>')
    message = message.replace('&amp;', '&').replace('&nbsp;', ' ')

    return message.strip()


def format_for_chat(response: str) -> str:
    """Format response for Webex Teams chat display with proper markdown"""
    # Chat message length limit (Webex is ~7439 chars)
    if len(response) > 7400:
        response = response[:7350] + "\n\n*[Response truncated due to length limits]*"

    # Enhanced Webex Markdown formatting for different types of responses
    if "Calculation:" in response:
        # Extract the calculation part for better formatting
        calc_match = re.search(r'Calculation:\s*(.+?)\s*=\s*(.+)', response)
        if calc_match:
            expression, result = calc_match.groups()
            response = f"## 🧮 Math Result\n\n**Expression:** `{expression}`  \n**Result:** `{result}`"
        else:
            response = f"## 🧮 Math Result\n\n{response}"

    elif "Current weather" in response:
        # Format weather info with better structure
        response = f"## 🌤️ Weather Information\n\n{response}"
        # Make temperature and conditions stand out
        response = re.sub(r'(\d+°F)', r'**\1**', response)
        response = re.sub(r'(Sunny|Cloudy|Rainy|Clear|Overcast|Partly cloudy)', r'**\1**', response)

    elif "Status Code:" in response:
        response = f"## 🌐 API Response\n\n```json\n{response}\n```"

    elif "Containment status:" in response or "Device ID:" in response or "Online status:" in response:
        response = f"## 🔒 CrowdStrike Information\n\n{response}"
        # Highlight important status information
        response = re.sub(r'(Contained|Normal|Online|Offline)', r'**\1**', response)
        response = re.sub(r'(Device ID:\s*[A-Za-z0-9-]+)', r'**\1**', response)

    elif "Error:" in response:
        response = f"## ⚠️ Error\n\n{response}"

    elif "Device Details for" in response:
        # Format device details with better structure
        lines = response.split('\n')
        formatted_lines = []
        for line in lines:
            if line.startswith('•'):
                # Make property names bold
                line = re.sub(r'•\s*([^:]+):', r'• **\1:**', line)
            formatted_lines.append(line)
        response = f"## 💻 Device Details\n\n" + '\n'.join(formatted_lines)

    elif response.startswith('🟢') or response.startswith('🟡') or response.startswith('🔴'):
        # Health check responses
        response = f"## 🏥 System Status\n\n{response}"

    elif "Available Commands:" in response:
        # Help command formatting
        response = response.replace('🤖 **Available Commands:**', '## 🤖 Available Commands')
        response = re.sub(r'•\s*([^•\n]+)', r'• **\1**', response)

    else:
        # For general responses, add some structure if it's a longer response
        if len(response) > 200 and '\n' in response:
            # If it looks like a structured response, add a header
            if any(keyword in response.lower() for keyword in ['search', 'found', 'document', 'policy', 'information']):
                response = f"## 📄 Information Found\n\n{response}"
            elif any(keyword in response.lower() for keyword in ['answer', 'result', 'solution']):
                response = f"## 💡 Answer\n\n{response}"

    # General markdown enhancements
    # Make URLs clickable (if they're not already)
    response = re.sub(r'(?<![\[(])(https?://[^\s)]+)(?![])])', r'[\1](\1)', response)

    # Enhance bullet points
    response = re.sub(r'^- ', '• ', response, flags=re.MULTILINE)

    # Make key-value pairs more readable
    response = re.sub(r'^([A-Za-z\s]+):\s*([^\n]+)$', r'**\1:** \2', response, flags=re.MULTILINE)

    return response


def health_check() -> str:
    """Enhanced health check with performance monitoring"""
    # Basic component status
    component_status = {
        'llm': llm is not None,
        'embeddings': embeddings_ollama is not None,
        'agent': agent_executor is not None,
        'rag': vector_store_retriever is not None,
        'crowdstrike': crowdstrike_client is not None
    }

    # Get performance stats
    perf_stats = performance_monitor.get_stats()
    session_stats = session_manager.get_stats()

    # Check for capacity warnings
    warning = performance_monitor.get_capacity_warning()

    # Build comprehensive status report
    if all(v for v in component_status.values()):
        status_icon = "🟢"
        status_text = "All systems operational"
    else:
        status_icon = "🟡"
        issues = [k for k, v in component_status.items() if not v]
        status_text = f"Issues detected: {', '.join(issues)}"

    # Add warning if system is under stress
    if warning:
        status_icon = "🟠"
        status_text += f" ⚠️ Capacity warning: {warning}"

    health_report = f"{status_icon} **{status_text}**\n\n"

    # Performance metrics with both current session and lifetime stats
    health_report += f"## 📊 Performance Metrics\n"
    health_report += f"• **Current Session Uptime:** {perf_stats['uptime_hours']:.1f} hours\n"
    health_report += f"• **Total Lifetime Uptime:** {perf_stats['total_uptime_hours']:.1f} hours\n"
    health_report += f"• **Current Users:** {perf_stats['concurrent_users']} (Peak Ever: {perf_stats['peak_concurrent_users']})\n"
    health_report += f"• **Queries (24h):** {perf_stats['total_queries_24h']}\n"
    health_report += f"• **Total Lifetime Queries:** {perf_stats['total_lifetime_queries']}\n"
    health_report += f"• **Avg Response Time:** {perf_stats['avg_response_time_seconds']}s\n"
    health_report += f"• **Cache Hit Rate:** {perf_stats['cache_hit_rate']}%\n"
    health_report += f"• **Session Errors:** {perf_stats['total_errors']} (Lifetime: {perf_stats['total_lifetime_errors']})\n\n"

    # System resources
    if perf_stats['system']['memory_percent']:
        health_report += f"## 💻 System Resources\n"
        health_report += f"• **Memory:** {perf_stats['system']['memory_percent']}% used ({perf_stats['system']['memory_available_gb']}GB free)\n"
        health_report += f"• **CPU:** {perf_stats['system']['cpu_percent']}%\n"
        health_report += f"• **Disk:** {perf_stats['system']['disk_percent']}% used ({perf_stats['system']['disk_free_gb']}GB free)\n\n"

    # Session info
    health_report += f"## 👥 Session Info\n"
    health_report += f"• **Active Users:** {session_stats['active_users']}\n"
    health_report += f"• **Total Users Ever:** {session_stats['total_users_ever']}\n"
    health_report += f"• **Active Interactions:** {session_stats['total_interactions']}"

    return health_report


# --- Shutdown Handler ---
import atexit
import signal


def shutdown_handler():
    """Save performance data on shutdown"""
    try:
        logging.info("Saving performance data before shutdown...")
        performance_monitor.save_data()
        logging.info("Performance data saved successfully")
    except Exception as e:
        logging.error(f"Error saving performance data on shutdown: {e}")


# Register shutdown handlers
atexit.register(shutdown_handler)
signal.signal(signal.SIGTERM, lambda signum, frame: shutdown_handler())
signal.signal(signal.SIGINT, lambda signum, frame: shutdown_handler())

# --- Tool Definitions ---
import requests


@tool
def get_weather_info(city: str) -> str:
    """
    Get current weather information for a specific city using OpenWeatherMap free API.
    Use this tool when asked about weather conditions.
    """
    # Using OpenWeatherMap free API - 1000 calls/day limit
    api_key = CONFIG.open_weather_map_api_key  # You'll need to get a free API key from openweathermap.org
    base_url = "http://api.openweathermap.org/data/2.5/weather"

    try:
        # Make API request
        params = {
            'q': city,
            'appid': api_key,
            'units': 'imperial'  # For Fahrenheit, use 'metric' for Celsius
        }

        response = requests.get(base_url, params=params, timeout=10)

        if response.status_code == 401:
            # Fallback to mock data if no API key is configured
            return _get_mock_weather(city)

        response.raise_for_status()
        data = response.json()

        # Extract weather information
        location = data['name']
        country = data['sys']['country']
        weather = data['weather'][0]
        main = data['main']
        wind = data.get('wind', {})

        # Format the weather information
        weather_info = f"Current weather in {location}, {country}: "
        weather_info += f"{weather['description'].title()}, "
        weather_info += f"{main['temp']:.0f}°F "

        if 'feels_like' in main:
            weather_info += f"(feels like {main['feels_like']:.0f}°F), "

        weather_info += f"humidity {main['humidity']}%"

        if wind.get('speed'):
            # Convert m/s to mph
            wind_mph = wind['speed'] * 2.237
            wind_dir = wind.get('deg', 0)
            # Convert degrees to cardinal direction
            directions = ["N", "NNE", "NE", "ENE", "E", "ESE", "SE", "SSE",
                          "S", "SSW", "SW", "WSW", "W", "WNW", "NW", "NNW"]
            dir_index = int((wind_dir + 11.25) / 22.5) % 16
            weather_info += f", wind {wind_mph:.0f} mph {directions[dir_index]}"

        return weather_info

    except requests.exceptions.HTTPError as e:
        if hasattr(e, 'response') and e.response.status_code == 404:
            return f"Weather data not available for '{city}'. Please check the city name and try again."
        else:
            return _get_mock_weather(city)
    except requests.exceptions.RequestException as e:
        # Fallback to mock data on network error
        return _get_mock_weather(city)
    except KeyError as e:
        return _get_mock_weather(city)
    except Exception as e:
        return _get_mock_weather(city)


def _get_mock_weather(city: str) -> str:
    """Fallback mock weather data when API is not available"""
    mock_data = {
        "new york": "Cloudy, 45°F, humidity 70%, wind 8 mph NW",
        "london": "Rainy, 52°F, humidity 85%, wind 12 mph SW",
        "tokyo": "Clear, 72°F, humidity 60%, wind 5 mph E",
        "paris": "Partly cloudy, 59°F, humidity 65%, wind 6 mph W",
        "sydney": "Sunny, 75°F, humidity 55%, wind 10 mph SE",
        "san francisco": "Sunny, 68°F, humidity 70%, wind 15 mph W",
        "berlin": "Overcast, 48°F, humidity 80%, wind 7 mph N"
    }

    city_lower = city.lower()
    if city_lower in mock_data:
        return f"Current weather in {city}: {mock_data[city_lower]} (Note: Using sample data - configure OpenWeatherMap API key for live data)"
    else:
        return f"Weather data not available for '{city}'. Supported sample cities: {', '.join(mock_data.keys())}"


# --- CrowdStrike Tools ---
@tool
def get_device_containment_status(hostname: str) -> str:
    """Get the containment status of a device from CrowdStrike by hostname."""
    if not crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    status = crowdstrike_client.get_device_containment_status(hostname)

    if status == 'Host not found in CS':
        return f"Hostname '{hostname}' was not found in CrowdStrike."

    if status:
        status_descriptions = {
            'normal': 'Normal - Device is not contained',
            'containment_pending': 'Containment Pending - Containment action initiated',
            'contained': 'Contained - Device is isolated from network',
            'lift_containment_pending': 'Lift Containment Pending - Uncontainment action initiated'
        }
        description = status_descriptions.get(status, f'Unknown status: {status}')
        return f"Containment status for '{hostname}': {description}"

    return f"Unable to retrieve containment status for hostname '{hostname}'."


@tool
def get_device_online_status(hostname: str) -> str:
    """Get the online status of a device from CrowdStrike by hostname."""
    if not crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    status = crowdstrike_client.get_device_online_state(hostname)

    if status:
        status_descriptions = {
            'online': 'Online - Device is currently connected',
            'offline': 'Offline - Device is not currently connected',
            'unknown': 'Unknown - Connection status unclear'
        }
        description = status_descriptions.get(status, f'Status: {status}')
        return f"Online status for '{hostname}': {description}"

    return f"Unable to retrieve online status for hostname '{hostname}'. Device may not exist in CrowdStrike."


@tool
def get_device_details_cs(hostname: str) -> str:
    """Get detailed information about a device from CrowdStrike by hostname."""
    if not crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    hostname = hostname.strip().upper()
    device_id = crowdstrike_client.get_device_id(hostname)

    if not device_id:
        return f"Hostname '{hostname}' was not found in CrowdStrike."

    details = crowdstrike_client.get_device_details(device_id)

    if details:
        info_parts = [
            f"Device Details for '{hostname}':",
            f"• Device ID: {device_id}",
            f"• Status: {details.get('status', 'Unknown')}",
            f"• Last Seen: {details.get('last_seen', 'Unknown')}",
            f"• OS Version: {details.get('os_version', 'Unknown')}",
            f"• Product Type: {details.get('product_type_desc', 'Unknown')}",
            f"• Chassis Type: {details.get('chassis_type_desc', 'Unknown')}",
        ]

        tags = details.get('tags', [])
        if tags:
            info_parts.append(f"• Tags: {', '.join(tags)}")
        else:
            info_parts.append("• Tags: None")

        return "\n".join(info_parts)

    return f"Unable to retrieve detailed information for hostname '{hostname}'."


# --- RAG Helper Functions ---
def verify_specific_document_loading():
    """Verify that the specific document is loaded and indexed properly"""
    import os
    from langchain_community.document_loaders import UnstructuredWordDocumentLoader

    target_doc = "GDnR_Blocking_Network_Access_Control _10022024.docx"
    doc_path = os.path.join(PDF_DIRECTORY_PATH, target_doc)

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


def _load_documents_from_folder(folder_path: str):
    """
    Enhanced document loading with specific verification for target document.
    """
    documents = []
    pdf_loaded = False
    target_doc_loaded = False

    if not os.path.exists(folder_path):
        logging.warning(f"Folder does not exist: {folder_path}")
        return documents

    # First, verify our target document can be loaded
    verify_specific_document_loading()

    for fname in os.listdir(folder_path):
        fpath = os.path.join(folder_path, fname)
        if not os.path.isfile(fpath):
            continue

        ext = os.path.splitext(fname)[1].lower()

        try:
            if ext == ".pdf" and not pdf_loaded:
                # PyPDFDirectoryLoader loads all PDFs at once
                loader = PyPDFDirectoryLoader(folder_path)
                documents.extend(loader.load())
                pdf_loaded = True
                logging.info(f"Loaded PDF documents from {folder_path}")
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


def _build_and_save_vector_store(pdf_folder_path: str, index_path: str, current_embeddings):
    """Build and save the vector store from documents with improved chunking for better detail retrieval"""
    if not os.path.exists(pdf_folder_path):
        logging.warning(f"PDF directory '{pdf_folder_path}' does not exist. Skipping vector store build.")
        return False

    files_in_dir = os.listdir(pdf_folder_path)
    if not files_in_dir:
        logging.warning(f"PDF directory '{pdf_folder_path}' is empty. Skipping vector store build.")
        return False

    logging.info(f"Loading documents from: {pdf_folder_path}")
    documents = _load_documents_from_folder(pdf_folder_path)

    if not documents:
        logging.warning(f"No documents could be loaded from '{pdf_folder_path}'. Skipping vector store build.")
        return False

    logging.info(f"Loaded {len(documents)} documents.")

    # Enhanced text splitting for better content preservation
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1500,  # Increased from 1000 to preserve more context
        chunk_overlap=300,  # Increased from 200 for better continuity
        length_function=len,
        separators=["\n\n", "\n", ". ", "! ", "? ", " ", ""]  # Better splitting points
    )
    texts = text_splitter.split_documents(documents)
    logging.info(f"Split into {len(texts)} text chunks with improved chunking strategy.")

    # Create vector store
    logging.info("Creating vector store with FAISS and Ollama embeddings...")
    try:
        db = FAISS.from_documents(texts, current_embeddings)

        # Save the vector store
        os.makedirs(os.path.dirname(index_path), exist_ok=True)
        db.save_local(index_path)
        logging.info(f"Vector store saved to: {index_path}")
        return True

    except Exception as e:
        logging.error(f"Error creating or saving vector store: {e}", exc_info=True)
        return False


# --- Initialization Function ---
def initialize_model_and_agent():
    """Initialize the LLM, embeddings, and agent"""
    global llm, embeddings_ollama, vector_store_retriever, agent_executor, crowdstrike_client

    # Check if already initialized to avoid redundant initialization
    if agent_executor is not None:
        logging.info("Model and Agent already initialized.")
        return True

    try:
        logging.info(f"Initializing Langchain model: {OLLAMA_LLM_MODEL_NAME}...")
        llm = ChatOllama(model=OLLAMA_LLM_MODEL_NAME, temperature=0.1)
        logging.info(f"Langchain model {OLLAMA_LLM_MODEL_NAME} initialized.")

        logging.info(f"Initializing Ollama embeddings with model: {OLLAMA_EMBEDDING_MODEL_NAME}...")
        embeddings_ollama = OllamaEmbeddings(model=OLLAMA_EMBEDDING_MODEL_NAME)
        logging.info("Ollama embeddings initialized.")

        # Initialize CrowdStrike client
        logging.info("Initializing CrowdStrike client...")
        crowdstrike_client = CrowdStrikeClient()
        # Test the connection
        token = crowdstrike_client.get_access_token()
        if token:
            logging.info("CrowdStrike client initialized successfully.")
        else:
            logging.warning("CrowdStrike client failed to get access token. CrowdStrike tools will be disabled.")
            crowdstrike_client = None

        # Ensure PDF directory exists
        if not os.path.exists(PDF_DIRECTORY_PATH):
            try:
                os.makedirs(PDF_DIRECTORY_PATH)
                logging.info(f"Created PDF directory for RAG: {PDF_DIRECTORY_PATH}")
            except OSError as e:
                logging.error(f"Could not create PDF directory {PDF_DIRECTORY_PATH}: {e}")

        # Initialize base tools
        all_tools = [get_weather_info]

        # Add CrowdStrike tools if available
        if crowdstrike_client:
            all_tools.extend([
                get_device_containment_status,
                get_device_online_status,
                get_device_details_cs
            ])
            logging.info("CrowdStrike tools added to agent.")

        # Load or build vector store for RAG
        vector_store = None
        if os.path.exists(FAISS_INDEX_PATH):
            try:
                logging.info(f"Loading existing FAISS index from: {FAISS_INDEX_PATH}")
                vector_store = FAISS.load_local(
                    FAISS_INDEX_PATH,
                    embeddings_ollama,
                    allow_dangerous_deserialization=True
                )
                logging.info("FAISS index loaded successfully.")
            except Exception as e:
                logging.error(f"Error loading FAISS index: {e}. Will attempt to rebuild.", exc_info=True)
                if _build_and_save_vector_store(PDF_DIRECTORY_PATH, FAISS_INDEX_PATH, embeddings_ollama):
                    vector_store = FAISS.load_local(
                        FAISS_INDEX_PATH,
                        embeddings_ollama,
                        allow_dangerous_deserialization=True
                    )
        else:
            logging.info(f"FAISS index not found at {FAISS_INDEX_PATH}. Building new vector store.")
            if _build_and_save_vector_store(PDF_DIRECTORY_PATH, FAISS_INDEX_PATH, embeddings_ollama):
                vector_store = FAISS.load_local(
                    FAISS_INDEX_PATH,
                    embeddings_ollama,
                    allow_dangerous_deserialization=True
                )

        # Add RAG tool if vector store is available
        if vector_store:
            # Increase retrieval context for more detailed responses
            vector_store_retriever = vector_store.as_retriever(search_kwargs={"k": 5})  # Increased from 3 to 5
            rag_tool = create_retriever_tool(
                vector_store_retriever,
                "search_local_documents",
                "Searches and returns information from local PDF and Word documents. Use this for questions about policies, reports, or specific documented information. This tool returns detailed content from relevant documents."
            )
            all_tools.append(rag_tool)
            logging.info("RAG tool (search_local_documents) initialized and added to agent tools.")
        else:
            logging.warning("Vector store not available. RAG tool for documents will not be available to the agent.")

        # Define the ReAct agent prompt - optimized for comprehensive responses with better control
        prompt_template = """You are an expert security documentation assistant. Your PRIMARY mission is to provide COMPREHENSIVE, DETAILED operational guidance by searching local security documents first, then providing expert knowledge.

CRITICAL EXECUTION RULES - FOLLOW THESE EXACTLY:
1. ALWAYS start by using the search_local_documents tool with the user's main keywords
2. If the first search yields limited results, try ONE additional search with related terms
3. After maximum 2 searches, you MUST provide a comprehensive answer based on available information
4. DO NOT continue searching indefinitely - provide your best response after 2 search attempts
5. If documents are found, extract ALL relevant details and quote specific procedures
6. If no relevant documents are found, provide expert security guidance based on best practices

RESPONSE CONSTRUCTION REQUIREMENTS:
When documents are found:
- Start with: "Based on [Document Name]..."
- Include complete step-by-step procedures with numbered steps
- Quote important warnings, requirements, and contact information
- Include ALL tools, URLs, teams, and technical details mentioned
- Add quality control steps and verification procedures
- Include timeline requirements and escalation procedures

When documents are not found or limited:
- Start with: "Based on security best practices..."
- Provide comprehensive procedural guidance using industry standards
- Include general security tools and methodologies
- Provide clear step-by-step instructions
- Include common verification steps and quality controls
- Add relevant warnings and considerations

SEARCH STRATEGY (Maximum 2 attempts):
- First search: Use main keywords from user question
- Second search (if needed): Use 2-3 related technical terms
- Then STOP searching and provide comprehensive response

FORMATTING FOR MAXIMUM CLARITY:
- Use clear headers (##) for major sections
- Use bullet points (•) for lists and requirements  
- Use numbered lists (1., 2., 3.) for sequential procedures
- Bold important warnings, tools, and key information
- Include specific technical details and configurations
- Provide complete operational context

You have access to the following tools:

{tools}

Use the following format:

Question: the input question you must answer
Thought: you should always think about what to do
Action: the action to take, should be one of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation can repeat N times)
Thought: I now know the final answer
Final Answer: the final answer to the original input question

Begin!

Question: {input}
Thought:{agent_scratchpad}"""

        prompt = ChatPromptTemplate.from_template(prompt_template)

        # Create the ReAct agent
        agent = create_react_agent(llm, all_tools, prompt)

        # Create agent executor with proper configuration
        agent_executor = AgentExecutor(
            agent=agent,
            tools=all_tools,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=6,  # Reduced to prevent infinite loops
            return_intermediate_steps=False
        )

        logging.info("Langchain Agent Executor initialized successfully with all tools.")
        return True

    except Exception as e:
        logging.error(f"Failed to initialize model and agent: {e}", exc_info=True)
        return False


def warmup():
    """Warm up the model with a simple query"""
    try:
        logging.info("Warming up the model...")
        test_response = ask("Hello, are you working?")
        if test_response:
            logging.info("Model warmup completed successfully")
            return True
        else:
            logging.warning("Model warmup returned empty response")
            return False
    except Exception as e:
        logging.error(f"Model warmup failed: {e}")
        return False


def reindex_pdfs_and_update_agent():
    """Triggers a re-build of the vector store and re-initializes the agent"""
    global agent_executor

    logging.info("Re-indexing PDFs and updating agent triggered.")

    if not llm or not embeddings_ollama:
        logging.error("LLM or Embeddings not initialized. Cannot re-index. Call initialize_model_and_agent() first.")
        return False

    # Rebuild vector store
    if _build_and_save_vector_store(PDF_DIRECTORY_PATH, FAISS_INDEX_PATH, embeddings_ollama):
        logging.info("PDFs re-indexed successfully. Re-initializing agent...")
        # Force re-initialization of the agent
        agent_executor = None
        success = initialize_model_and_agent()
        if success and agent_executor:
            logging.info("Agent re-initialized successfully with updated RAG tool.")
            return True
        else:
            logging.error("Failed to re-initialize agent after re-indexing.")
            return False
    else:
        logging.error("Failed to re-build vector store during re-index. Agent not updated.")
        return False


def force_rebuild_vector_store():
    """Force rebuild the vector store from scratch with better error handling"""
    global vector_store_retriever, agent_executor

    logging.info("Force rebuilding vector store...")

    if not embeddings_ollama:
        logging.error("Embeddings not initialized. Cannot rebuild vector store.")
        return False

    # Remove existing index if it exists
    if os.path.exists(FAISS_INDEX_PATH):
        try:
            import shutil
            shutil.rmtree(FAISS_INDEX_PATH)
            logging.info("Removed existing FAISS index")
        except Exception as e:
            logging.error(f"Failed to remove existing index: {e}")

    # Rebuild vector store
    success = _build_and_save_vector_store(PDF_DIRECTORY_PATH, FAISS_INDEX_PATH, embeddings_ollama)
    if success:
        logging.info("Vector store rebuilt successfully. Reinitializing agent...")
        # Reset global variables to force reinitialization
        vector_store_retriever = None
        agent_executor = None
        return initialize_model_and_agent()
    else:
        logging.error("Failed to rebuild vector store")
        return False


# --- Additional debugging function ---
def test_document_search(query: str = "network access control"):
    """Test the document search functionality directly"""
    if not vector_store_retriever:
        return "Vector store not initialized"

    try:
        # Test direct retrieval
        docs = vector_store_retriever.get_relevant_documents(query)
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


# --- Performance Monitoring ---
class PerformanceMonitor:
    """Thread-safe performance monitoring for Pokédex with persistent storage"""

    def __init__(self, max_response_time_samples: int = 1000):
        self._lock = threading.RLock()
        self._start_time = datetime.now()
        self._data_file = PERFORMANCE_DATA_PATH

        # Concurrent user tracking
        self._active_requests: Dict[str, datetime] = {}  # user_id -> start_time
        self._peak_concurrent_users = 0

        # Response time tracking (keep last 1000 samples)
        self._response_times = deque(maxlen=max_response_time_samples)

        # Query volume tracking (hourly buckets)
        self._hourly_queries = defaultdict(int)  # hour_key -> count

        # Error tracking
        self._error_count = 0
        self._last_error_time = None

        # Cache hit tracking
        self._cache_hits = 0
        self._cache_misses = 0

        # Query type tracking
        self._query_types = defaultdict(int)

        # Total lifetime stats (persistent across restarts)
        self._total_lifetime_queries = 0
        self._total_lifetime_errors = 0
        self._initial_start_time = datetime.now()

        # Load existing data if available
        self._load_persistent_data()

    def _load_persistent_data(self) -> None:
        """Load persistent performance data from file"""
        try:
            if os.path.exists(self._data_file):
                with open(self._data_file, 'r') as f:
                    data = json.load(f)

                # Restore persistent counters
                self._peak_concurrent_users = data.get('peak_concurrent_users', 0)
                self._error_count = data.get('total_errors', 0)
                self._cache_hits = data.get('cache_hits', 0)
                self._cache_misses = data.get('cache_misses', 0)
                self._total_lifetime_queries = data.get('total_lifetime_queries', 0)
                self._total_lifetime_errors = data.get('total_lifetime_errors', 0)

                # Restore query types
                if 'query_types' in data:
                    self._query_types = defaultdict(int, data['query_types'])

                # Restore hourly queries (only recent ones)
                if 'hourly_queries' in data:
                    current_time = datetime.now()
                    cutoff_time = current_time - timedelta(hours=48)
                    cutoff_hour = cutoff_time.strftime("%Y-%m-%d-%H")

                    for hour, count in data['hourly_queries'].items():
                        if hour >= cutoff_hour:
                            self._hourly_queries[hour] = count

                # Restore response times (last 200 samples for faster startup)
                if 'response_times' in data:
                    recent_times = data['response_times'][-200:]  # Only keep recent ones
                    self._response_times.extend(recent_times)

                # Restore timestamps
                if 'last_error_time' in data and data['last_error_time']:
                    self._last_error_time = datetime.fromisoformat(data['last_error_time'])

                if 'initial_start_time' in data:
                    self._initial_start_time = datetime.fromisoformat(data['initial_start_time'])

                logging.info(f"Loaded performance data: {self._total_lifetime_queries} lifetime queries, "
                             f"{self._error_count} total errors, peak {self._peak_concurrent_users} concurrent users")
            else:
                logging.info("No existing performance data found, starting fresh")

        except Exception as e:
            logging.error(f"Failed to load performance data: {e}")
            # Continue with defaults if loading fails

    def _save_persistent_data(self) -> None:
        """Save persistent performance data to file"""
        try:
            data = {
                'peak_concurrent_users': self._peak_concurrent_users,
                'total_errors': self._error_count,
                'cache_hits': self._cache_hits,
                'cache_misses': self._cache_misses,
                'total_lifetime_queries': self._total_lifetime_queries,
                'total_lifetime_errors': self._total_lifetime_errors,
                'query_types': dict(self._query_types),
                'hourly_queries': dict(self._hourly_queries),
                'response_times': list(self._response_times),
                'last_error_time': self._last_error_time.isoformat() if self._last_error_time else None,
                'initial_start_time': self._initial_start_time.isoformat(),
                'last_save_time': datetime.now().isoformat()
            }

            # Ensure directory exists
            os.makedirs(os.path.dirname(self._data_file), exist_ok=True)

            # Write to temp file first, then move (atomic operation)
            temp_file = self._data_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)

            os.replace(temp_file, self._data_file)

        except Exception as e:
            logging.error(f"Failed to save performance data: {e}")

    def start_request(self, user_id: str, query_type: str = "general") -> None:
        """Mark the start of a request for a user"""
        with self._lock:
            current_time = datetime.now()
            self._active_requests[user_id] = current_time

            # Update peak concurrent users
            concurrent_count = len(self._active_requests)
            if concurrent_count > self._peak_concurrent_users:
                self._peak_concurrent_users = concurrent_count

            # Track query volume by hour
            hour_key = current_time.strftime("%Y-%m-%d-%H")
            self._hourly_queries[hour_key] += 1

            # Track query types
            self._query_types[query_type] += 1

            # Increment lifetime counter
            self._total_lifetime_queries += 1

            # Clean up old hourly data (keep last 48 hours)
            cutoff_time = current_time - timedelta(hours=48)
            cutoff_hour = cutoff_time.strftime("%Y-%m-%d-%H")

            hours_to_remove = [
                hour for hour in self._hourly_queries.keys()
                if hour < cutoff_hour
            ]
            for hour in hours_to_remove:
                del self._hourly_queries[hour]

    def end_request(self, user_id: str, response_time_seconds: float, error: bool = False) -> None:
        """Mark the end of a request for a user"""
        with self._lock:
            # Remove from active requests
            if user_id in self._active_requests:
                del self._active_requests[user_id]

            # Track response time
            self._response_times.append(response_time_seconds)

            # Track errors
            if error:
                self._error_count += 1
                self._total_lifetime_errors += 1
                self._last_error_time = datetime.now()

            # Periodically save data (every 10 requests)
            if self._total_lifetime_queries % 10 == 0:
                self._save_persistent_data()

    def record_cache_hit(self) -> None:
        """Record a cache hit"""
        with self._lock:
            self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss"""
        with self._lock:
            self._cache_misses += 1

    def get_concurrent_users(self) -> int:
        """Get current number of concurrent users"""
        with self._lock:
            # Clean up stale requests (older than 5 minutes)
            current_time = datetime.now()
            stale_cutoff = current_time - timedelta(minutes=5)

            stale_users = [
                user_id for user_id, start_time in self._active_requests.items()
                if start_time < stale_cutoff
            ]

            for user_id in stale_users:
                del self._active_requests[user_id]

            return len(self._active_requests)

    def get_average_response_time(self) -> float:
        """Get average response time in seconds"""
        with self._lock:
            if not self._response_times:
                return 0.0
            return sum(self._response_times) / len(self._response_times)

    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()

            return {
                'process_memory_mb': memory_info.rss / 1024 / 1024,
                'process_memory_percent': process.memory_percent(),
                'system_memory_percent': system_memory.percent,
                'system_memory_available_gb': system_memory.available / 1024 / 1024 / 1024,
                'system_memory_total_gb': system_memory.total / 1024 / 1024 / 1024
            }
        except Exception as e:
            logging.error(f"Error getting memory usage: {e}")
            return {
                'process_memory_mb': 0,
                'process_memory_percent': 0,
                'system_memory_percent': 0,
                'system_memory_available_gb': 0,
                'system_memory_total_gb': 0
            }

    def get_queries_per_hour(self) -> Dict[str, int]:
        """Get query volume for the last N hours"""
        with self._lock:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=24)
            cutoff_hour = cutoff_time.strftime("%Y-%m-%d-%H")

            return {
                hour: count for hour, count in self._hourly_queries.items()
                if hour >= cutoff_hour
            }

    def get_total_queries_24h(self) -> int:
        """Get total queries in the last 24 hours"""
        queries_per_hour = self.get_queries_per_hour()
        return sum(queries_per_hour.values())

    def get_stats(self) -> Dict:
        """Get comprehensive performance statistics"""
        with self._lock:
            current_time = datetime.now()
            uptime_hours = (current_time - self._start_time).total_seconds() / 3600
            total_uptime_hours = (current_time - self._initial_start_time).total_seconds() / 3600

            memory_stats = self.get_memory_usage()

            # Get system stats
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
                disk_usage = psutil.disk_usage('/')
                disk_percent = (disk_usage.used / disk_usage.total) * 100
                disk_free_gb = disk_usage.free / 1024 / 1024 / 1024
            except Exception as e:
                logging.error(f"Error getting system stats: {e}")
                cpu_percent = 0
                disk_percent = 0
                disk_free_gb = 0

            # Calculate cache hit rate
            total_cache_operations = self._cache_hits + self._cache_misses
            cache_hit_rate = (self._cache_hits / total_cache_operations * 100) if total_cache_operations > 0 else 0

            return {
                'uptime_hours': uptime_hours,
                'total_uptime_hours': total_uptime_hours,
                'concurrent_users': self.get_concurrent_users(),
                'peak_concurrent_users': self._peak_concurrent_users,
                'avg_response_time_seconds': round(self.get_average_response_time(), 2),
                'total_queries_24h': self.get_total_queries_24h(),
                'total_lifetime_queries': self._total_lifetime_queries,
                'total_response_samples': len(self._response_times),
                'total_errors': self._error_count,
                'total_lifetime_errors': self._total_lifetime_errors,
                'last_error_time': self._last_error_time.isoformat() if self._last_error_time else None,
                'cache_hit_rate': round(cache_hit_rate, 1),
                'cache_hits': self._cache_hits,
                'cache_misses': self._cache_misses,
                'query_types': dict(self._query_types),
                'system': {
                    'memory_percent': round(memory_stats['system_memory_percent'], 1),
                    'memory_available_gb': round(memory_stats['system_memory_available_gb'], 1),
                    'memory_total_gb': round(memory_stats['system_memory_total_gb'], 1),
                    'process_memory_mb': round(memory_stats['process_memory_mb'], 1),
                    'process_memory_percent': round(memory_stats['process_memory_percent'], 1),
                    'cpu_percent': round(cpu_percent, 1),
                    'disk_percent': round(disk_percent, 1),
                    'disk_free_gb': round(disk_free_gb, 1)
                }
            }

    def get_capacity_warning(self) -> Optional[str]:
        """Check if system is under stress and return warning message"""
        with self._lock:
            warnings = []

            # Check concurrent users
            concurrent = self.get_concurrent_users()
            if concurrent > 50:
                warnings.append(f"High concurrent users: {concurrent}")

            # Check memory usage
            memory_stats = self.get_memory_usage()
            if memory_stats['system_memory_percent'] > 85:
                warnings.append(f"High memory usage: {memory_stats['system_memory_percent']:.1f}%")

            # Check response time
            avg_response = self.get_average_response_time()
            if avg_response > 10:
                warnings.append(f"Slow response time: {avg_response:.1f}s")

            # Check error rate (if more than 10 errors in last hour)
            if self._error_count > 10:
                warnings.append(f"High error count: {self._error_count}")

            return "; ".join(warnings) if warnings else None

    def save_data(self) -> None:
        """Manually save performance data (useful for shutdown)"""
        self._save_persistent_data()

    def reset_stats(self) -> None:
        """Reset all statistics (useful for testing)"""
        with self._lock:
            self._start_time = datetime.now()
            self._active_requests.clear()
            self._peak_concurrent_users = 0
            self._response_times.clear()
            self._hourly_queries.clear()
            self._error_count = 0
            self._last_error_time = None
            self._cache_hits = 0
            self._cache_misses = 0
            self._query_types.clear()
            self._total_lifetime_queries = 0
            self._total_lifetime_errors = 0
            self._initial_start_time = datetime.now()

            # Save the reset state
            self._save_persistent_data()


# Initialize global performance monitor and session manager after class definitions
performance_monitor = PerformanceMonitor()
session_manager = SessionManager(session_timeout_hours=24, max_interactions_per_user=10)


# --- Main Ask Function with Performance Tracking ---
def ask(user_message: str, user_id: str = "default", room_id: str = "default") -> str:
    """
    Main function to process user queries with comprehensive performance tracking.

    Args:
        user_message: The user's question or command
        user_id: Unique identifier for the user
        room_id: Unique identifier for the room/session

    Returns:
        Formatted response string
    """
    start_time = time.time()
    error_occurred = False
    query_type = "general"

    try:
        # Preprocess the message
        cleaned_message = preprocess_message(user_message)

        if not cleaned_message.strip():
            performance_monitor.record_cache_hit()  # Quick response, count as cache hit
            return "I didn't receive a message. Please ask me something!"

        # Determine query type for better tracking (simplified)
        message_lower = cleaned_message.lower()
        if any(word in message_lower for word in ['weather', 'temperature', 'forecast']):
            query_type = "weather"
        elif any(word in message_lower for word in ['containment', 'device', 'hostname']) and 'crowdstrike' in message_lower:
            query_type = "crowdstrike"
        elif message_lower in ['status', 'health', 'health check', 'help', 'commands', 'what can you do', 'what can you do?', 'metrics', 'performance', 'stats', 'metrics summary', 'quick stats']:
            query_type = "status"
        else:
            # Default to RAG for all other queries - let the agent decide which tools to use
            query_type = "rag"

        # Start performance tracking with correct query type
        performance_monitor.start_request(user_id, query_type)

        # Handle special commands
        if message_lower in ['status', 'health', 'health check']:
            performance_monitor.record_cache_hit()
            response = health_check()
        elif message_lower in ['help', 'commands', 'what can you do', 'what can you do?']:
            performance_monitor.record_cache_hit()
            response = get_help_message()
        elif message_lower in ['metrics', 'performance', 'stats']:
            performance_monitor.record_cache_hit()
            response = get_performance_report()
        elif message_lower in ['metrics summary', 'quick stats']:
            performance_monitor.record_cache_hit()
            # Format the summary nicely for chat
            summary = get_metrics_summary()
            response = f"""## 📊 Quick Metrics Summary

• **Concurrent Users:** {summary['concurrent_users']} (Peak: {summary['peak_concurrent_users']})
• **Avg Response Time:** {summary['avg_response_time_seconds']}s
• **24h Queries:** {summary['total_queries_24h']}
• **Memory Usage:** {summary['memory_usage_percent']}%
• **CPU Usage:** {summary['cpu_usage_percent']}%
• **Cache Hit Rate:** {summary['cache_hit_rate']}%
• **Total Errors:** {summary['total_errors']}
• **Uptime:** {summary['uptime_hours']:.1f} hours
{f"⚠️ **Warning:** {summary['capacity_warning']}" if summary['capacity_warning'] else "✅ **Status:** All systems normal"}"""
        else:
            # Check if we need to initialize the agent
            if not agent_executor:
                error_occurred = True
                return "❌ Bot is not properly initialized. Please contact an administrator."

            # Record cache miss for complex queries
            performance_monitor.record_cache_miss()

            # Get conversation context
            context = session_manager.get_context(user_id, limit=3)

            # Prepare the query with context
            if context:
                full_query = f"Context from recent conversation:\n{context}\n\nCurrent question: {cleaned_message}"
            else:
                full_query = cleaned_message

            # Process with the agent
            try:
                result = agent_executor.invoke({"input": full_query})
                response = result.get('output', 'I encountered an issue processing your request.')
            except Exception as agent_error:
                error_occurred = True
                logging.error(f"Agent execution failed: {agent_error}", exc_info=True)
                response = f"I encountered an error while processing your request: {str(agent_error)}"

        # Format the response for chat
        formatted_response = format_for_chat(response)

        # Store interaction in session
        session_manager.add_interaction(user_id, cleaned_message, formatted_response)

        return formatted_response

    except Exception as e:
        error_occurred = True
        logging.error(f"Error in ask function: {e}", exc_info=True)
        return f"❌ I encountered an unexpected error: {str(e)}"

    finally:
        # Record performance metrics
        end_time = time.time()
        response_time = end_time - start_time
        performance_monitor.end_request(user_id, response_time, error_occurred)


def get_help_message() -> str:
    """Generate help message with available commands"""
    help_text = """🤖 **Available Commands:**

• **Weather**: Ask about weather in various cities
  - "What's the weather in Tokyo?"
  - "Weather in San Francisco"

• **Document Search**: Search local documents and policies
  - "Search for information about security policies"
  - "Find documentation about procedures"

• **CrowdStrike**: Check device status (if available)
  - "Check containment status for HOSTNAME"
  - "Is HOSTNAME online?"
  - "Get device details for HOSTNAME"

• **System Status**: Check bot health and performance
  - "status" or "health check"

• **General Questions**: Ask me anything else!
  - I can help with general information and conversation

💡 **Tips:**
- You can ask follow-up questions - I remember our recent conversation
- Be specific in your questions for better results
- Use "status" to check my current performance and health"""

    return help_text


# --- Additional Metrics Functions ---
def get_performance_report() -> str:
    """Generate a detailed performance report"""
    stats = performance_monitor.get_stats()

    report = f"""## 📊 Detailed Performance Report

### 🕐 Uptime & Usage
• **System Uptime:** {stats['uptime_hours']:.1f} hours
• **Current Active Users:** {stats['concurrent_users']}
• **Peak Concurrent Users:** {stats['peak_concurrent_users']}
• **Total Queries (24h):** {stats['total_queries_24h']}

### ⚡ Response Performance
• **Average Response Time:** {stats['avg_response_time_seconds']}s
• **Total Response Samples:** {stats['total_response_samples']}
• **Cache Hit Rate:** {stats['cache_hit_rate']}%
• **Cache Hits:** {stats['cache_hits']}
• **Cache Misses:** {stats['cache_misses']}

### 🚫 Error Tracking
• **Total Errors:** {stats['total_errors']}
• **Last Error:** {stats['last_error_time'] or 'None'}

### 💻 System Resources
• **System Memory:** {stats['system']['memory_percent']}% used
• **Available Memory:** {stats['system']['memory_available_gb']}GB
• **Process Memory:** {stats['system']['process_memory_mb']}MB ({stats['system']['process_memory_percent']}%)
• **CPU Usage:** {stats['system']['cpu_percent']}%
• **Disk Usage:** {stats['system']['disk_percent']}% used
• **Free Disk Space:** {stats['system']['disk_free_gb']}GB

### 📈 Query Types Distribution"""

    # Add query types
    if stats['query_types']:
        for query_type, count in stats['query_types'].items():
            report += f"\n• **{query_type.title()}:** {count} queries"
    else:
        report += "\n• No query data available yet"

    # Add hourly breakdown
    hourly_queries = performance_monitor.get_queries_per_hour()
    if hourly_queries:
        report += f"\n\n### 📅 Hourly Query Volume (Last 24h)"
        recent_hours = sorted(hourly_queries.keys())[-12:]  # Show last 12 hours
        for hour in recent_hours:
            hour_display = datetime.strptime(hour, "%Y-%m-%d-%H").strftime("%m/%d %H:00")
            report += f"\n• **{hour_display}:** {hourly_queries[hour]} queries"

    return report


def get_metrics_summary() -> Dict:
    """Get a summary of key metrics for API/programmatic access"""
    stats = performance_monitor.get_stats()

    return {
        'concurrent_users': stats['concurrent_users'],
        'peak_concurrent_users': stats['peak_concurrent_users'],
        'avg_response_time_seconds': stats['avg_response_time_seconds'],
        'total_queries_24h': stats['total_queries_24h'],
        'memory_usage_percent': stats['system']['memory_percent'],
        'cpu_usage_percent': stats['system']['cpu_percent'],
        'cache_hit_rate': stats['cache_hit_rate'],
        'total_errors': stats['total_errors'],
        'uptime_hours': stats['uptime_hours'],
        'capacity_warning': performance_monitor.get_capacity_warning()
    }
