# /services/my_model.py
import os
import logging
import requests
import json
import re
import threading
from datetime import datetime, timedelta
from collections import defaultdict

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

# CrowdStrike integration
from services.crowdstrike import CrowdStrikeClient

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Configuration ---
PDF_DIRECTORY_PATH = os.path.join(os.path.dirname(__file__), "..", "local_pdfs_docs")
FAISS_INDEX_PATH = os.path.join(os.path.dirname(__file__), "..", "faiss_index_ollama")
OLLAMA_LLM_MODEL_NAME = "qwen2.5:14b"
OLLAMA_EMBEDDING_MODEL_NAME = "nomic-embed-text"

# --- Global Variables ---
llm = None
embeddings_ollama = None
vector_store_retriever = None
agent_executor = None
crowdstrike_client: Optional[CrowdStrikeClient] = None  # CrowdStrike client instance


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


# Initialize global session manager
session_manager = SessionManager(session_timeout_hours=24, max_interactions_per_user=10)


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
    """Quick health check of all components"""
    status = {
        'llm': llm is not None,
        'embeddings': embeddings_ollama is not None,
        'agent': agent_executor is not None,
        'rag': vector_store_retriever is not None,
        'crowdstrike': crowdstrike_client is not None
    }

    if all(v for v in status.values()):
        return "🟢 All systems operational"
    else:
        issues = [k for k, v in status.items() if not v]
        return f"🟡 Issues detected: {', '.join(issues)}"


# --- Tool Definitions ---
@tool
def get_weather_info(city: str) -> str:
    """
    Get current weather information for a specific city.
    Use this tool when asked about weather conditions.
    """
    weather_data = {
        "san francisco": "Sunny, 68°F, light breeze from the west",
        "new york": "Cloudy, 45°F, chance of rain later",
        "london": "Rainy, 52°F, heavy clouds and drizzle",
        "tokyo": "Clear, 72°F, humid with light winds",
        "paris": "Partly cloudy, 59°F, gentle breeze",
        "sydney": "Sunny, 75°F, clear skies",
        "berlin": "Overcast, 48°F, light wind"
    }
    city_lower = city.lower()
    if city_lower in weather_data:
        return f"Current weather in {city}: {weather_data[city_lower]}"
    else:
        available_cities = ", ".join(weather_data.keys())
        return f"Weather data not available for {city}. I have data for: {available_cities}"


@tool
def calculate_math(expression: str) -> str:
    """
    Calculate basic math expressions safely.
    Use this tool for mathematical calculations.
    Example: '2 + 3 * 4' or '(10 + 5) / 3'
    """
    try:
        # Enhanced security check
        allowed_chars = set('0123456789+-*/.() ')
        expression_clean = expression.replace(' ', '')

        if not expression.strip():
            return "Error: Empty expression provided."

        if not all(c in allowed_chars for c in expression_clean):
            return "Error: Invalid expression. Only basic math operations (+, -, *, /, parentheses) and numbers are allowed."

        # Additional security: check for dangerous patterns
        dangerous_patterns = ['__', 'import', 'exec', 'eval', 'open', 'file']
        if any(pattern in expression.lower() for pattern in dangerous_patterns):
            return "Error: Expression contains prohibited content."

        result = eval(expression)
        return f"Calculation: {expression} = {result}"

    except ZeroDivisionError:
        return "Error: Division by zero is not allowed."
    except SyntaxError:
        return "Error: Invalid mathematical expression syntax."
    except Exception as e:
        return f"Math error: {str(e)}"


@tool
def call_api_endpoint(endpoint: str, method: str = "GET", params: dict = None) -> str:
    """
    Make API calls to various external endpoints.
    Use this tool when asked to fetch data from a specific URL or API.
    Args:
        endpoint: The API endpoint URL
        method: HTTP method (GET, POST, etc.)
        params: Parameters to send with the request (for POST/PUT)
    """
    # Timeout for API calls
    timeout = 10

    try:
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Python-Agent/1.0'
        }

        logging.info(f"Making {method} request to: {endpoint}")

        if method.upper() == "GET":
            response = requests.get(endpoint, params=params, headers=headers, timeout=timeout)
        elif method.upper() == "POST":
            response = requests.post(endpoint, json=params, headers=headers, timeout=timeout)
        elif method.upper() == "PUT":
            response = requests.put(endpoint, json=params, headers=headers, timeout=timeout)
        elif method.upper() == "DELETE":
            response = requests.delete(endpoint, headers=headers, timeout=timeout)
        else:
            return f"Unsupported HTTP method: {method}"

        result = f"Status Code: {response.status_code}\n"

        try:
            json_data = response.json()
            # Limit response size
            json_str = json.dumps(json_data, indent=2)
            if len(json_str) > 1000:
                json_str = json_str[:950] + "...\n[Response truncated]"
            result += f"JSON Response:\n{json_str}"
        except json.JSONDecodeError:
            text_response = response.text[:800]
            if len(response.text) > 800:
                text_response += "...\n[Response truncated]"
            result += f"Text Response: {text_response}"
        except Exception as e:
            result += f"Error processing response: {str(e)}"

        return result

    except requests.exceptions.Timeout:
        return f"Request timed out after {timeout} seconds"
    except requests.exceptions.RequestException as e:
        return f"Network error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"


# --- CrowdStrike Tools ---
@tool
def get_device_containment_status(hostname: str) -> str:
    """
    Get the containment status of a device from CrowdStrike by hostname.
    Use this tool when asked about device containment, isolation, or security status.
    Args:
        hostname: The hostname/computer name to check
    """
    if not crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    try:
        logging.info(f"Checking containment status for hostname: {hostname}")

        # Clean up hostname (remove spaces, convert to uppercase if needed)
        hostname = hostname.strip().upper()

        status = crowdstrike_client.get_device_containment_status(hostname)

        if status == 'Host not found in CS':
            return f"Hostname '{hostname}' was not found in CrowdStrike."
        elif status:
            # Map CrowdStrike status codes to readable descriptions
            status_descriptions = {
                'normal': 'Normal - Device is not contained',
                'containment_pending': 'Containment Pending - Containment action initiated',
                'contained': 'Contained - Device is isolated from network',
                'lift_containment_pending': 'Lift Containment Pending - Uncontainment action initiated'
            }
            description = status_descriptions.get(status, f'Unknown status: {status}')
            return f"Containment status for '{hostname}': {description}"
        else:
            return f"Unable to retrieve containment status for hostname '{hostname}'."

    except Exception as e:
        logging.error(f"Error checking containment status for {hostname}: {e}")
        return f"Error retrieving containment status for '{hostname}': {str(e)}"


@tool
def get_device_online_status(hostname: str) -> str:
    """
    Get the online status of a device from CrowdStrike by hostname.
    Use this tool when asked about device connectivity or online state.
    Args:
        hostname: The hostname/computer name to check
    """
    if not crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    try:
        logging.info(f"Checking online status for hostname: {hostname}")

        # Clean up hostname
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
        else:
            return f"Unable to retrieve online status for hostname '{hostname}'. Device may not exist in CrowdStrike."

    except Exception as e:
        logging.error(f"Error checking online status for {hostname}: {e}")
        return f"Error retrieving online status for '{hostname}': {str(e)}"


@tool
def get_device_details_cs(hostname: str) -> str:
    """
    Get detailed information about a device from CrowdStrike by hostname.
    Use this tool when asked for comprehensive device information, details, or properties.
    Args:
        hostname: The hostname/computer name to get details for
    """
    if not crowdstrike_client:
        return "Error: CrowdStrike service is not initialized."

    try:
        logging.info(f"Getting device details for hostname: {hostname}")

        # Clean up hostname
        hostname = hostname.strip().upper()

        # First get device ID
        device_id = crowdstrike_client.get_device_id(hostname)
        if not device_id:
            return f"Hostname '{hostname}' was not found in CrowdStrike."

        # Get detailed information
        details = crowdstrike_client.get_device_details(device_id)

        if details:
            # Format key information for chat display
            info_parts = [
                f"Device Details for '{hostname}':",
                f"• Device ID: {device_id}",
                f"• Status: {details.get('status', 'Unknown')}",
                f"• Last Seen: {details.get('last_seen', 'Unknown')}",
                f"• OS Version: {details.get('os_version', 'Unknown')}",
                f"• Product Type: {details.get('product_type_desc', 'Unknown')}",
                f"• Chassis Type: {details.get('chassis_type_desc', 'Unknown')}",
            ]

            # Add tags if available
            tags = details.get('tags', [])
            if tags:
                info_parts.append(f"• Tags: {', '.join(tags)}")
            else:
                info_parts.append("• Tags: None")

            return "\n".join(info_parts)
        else:
            return f"Unable to retrieve detailed information for hostname '{hostname}'."

    except Exception as e:
        logging.error(f"Error getting device details for {hostname}: {e}")
        return f"Error retrieving device details for '{hostname}': {str(e)}"


# --- RAG Helper Functions ---
def _load_documents_from_folder(folder_path: str):
    """
    Loads documents from a folder, supporting PDF and Word (.doc, .docx) files.
    Returns a list of Document objects.
    """
    documents = []
    pdf_loaded = False

    if not os.path.exists(folder_path):
        logging.warning(f"Folder does not exist: {folder_path}")
        return documents

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
                documents.extend(doc_content)
                logging.info(f"Loaded Word document: {fname}")
        except Exception as e:
            logging.error(f"Failed to load {fname}: {e}")

    return documents


def _build_and_save_vector_store(pdf_folder_path: str, index_path: str, current_embeddings):
    """Build and save the vector store from documents"""
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

    # Split documents into chunks
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        length_function=len
    )
    texts = text_splitter.split_documents(documents)
    logging.info(f"Split into {len(texts)} text chunks.")

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
        all_tools = [get_weather_info, calculate_math, call_api_endpoint]

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
            vector_store_retriever = vector_store.as_retriever(search_kwargs={"k": 3})
            rag_tool = create_retriever_tool(
                vector_store_retriever,
                "search_local_documents",
                "Searches and returns information from local PDF and Word documents. Use this for questions about policies, reports, or specific documented information."
            )
            all_tools.append(rag_tool)
            logging.info("RAG tool (search_local_documents) initialized and added to agent tools.")
        else:
            logging.warning("Vector store not available. RAG tool for documents will not be available to the agent.")

        # Define the ReAct agent prompt
        prompt_template = """
        Answer the following questions as best you can. You have access to the following tools:

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
        Thought:{agent_scratchpad}
        """
        prompt = ChatPromptTemplate.from_template(prompt_template)

        # Create the ReAct agent
        agent = create_react_agent(llm, all_tools, prompt)

        # Create agent executor
        agent_executor = AgentExecutor(
            agent=agent,
            tools=all_tools,
            verbose=True,
            handle_parsing_errors=True,
            max_iterations=10,  # Prevent infinite loops
            early_stopping_method="generate"
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


# --- Session Management ---
def add_to_session(user_id: str, query: str, response: str):
    """Add query and response to user session"""
    session_manager.add_interaction(user_id, query, response)


def get_session_context(user_id: str, limit: int = 3) -> str:
    """Get recent conversation context for a user"""
    return session_manager.get_context(user_id, limit)


# --- Main Function for User Queries ---
def ask(user_query: str, user_id: Optional[str] = None, room_id: Optional[str] = None) -> str:
    """
    Answer a user's query using the Langchain agent.
    Enhanced with session management and chat formatting.
    """
    # Preprocess the query
    user_query = preprocess_message(user_query)

    # Handle special commands
    if user_query.lower() in ['status', 'health', 'ping']:
        return health_check()

    # Handle greeting messages
    if user_query.lower() in ['hello', 'hi', 'hey', 'greetings', 'good morning', 'good afternoon', 'good evening']:
        greeting_response = ("👋 **Hello! I am Pokedex, your friendly neighborhood Q&A bot.**\n\n"
                             "## 🎯 What I'm trained on:\n"
                             "• GDnR documents and company policies\n"
                             "• Technical documentation and procedures\n\n"
                             "## 🛠️ Tools I have access to:\n"
                             "• 🔒 **CrowdStrike** - Device status, containment, and security info\n"
                             "• 🌤️ **Weather** - Current conditions for various cities\n"
                             "• 🧮 **Calculator** - Mathematical calculations\n"
                             "• 📄 **Document Search** - Search through uploaded PDFs and Word docs\n"
                             "• 🌐 **API Calls** - Make requests to internal endpoints\n\n"
                             "## ⚠️ Important Note:\n"
                             "I don't have access to the general internet, but I can help with internal resources and tools!\n\n"
                             "💬 **Ready to help!** Feel free to ask me anything or type `help` to see all available commands.")
        return greeting_response

    if user_query.lower() in ['help', 'commands']:
        help_text = ("🤖 **Available Commands:**\n"
                     "• Ask me questions about uploaded documents\n"
                     "• Get weather info for cities\n"
                     "• Perform math calculations\n"
                     "• Make API calls to external services\n")

        # Add CrowdStrike commands if client is available
        if crowdstrike_client:
            help_text += ("• Check device containment status from CrowdStrike\n"
                          "• Check device online status from CrowdStrike\n"
                          "• Get device details from CrowdStrike\n")

        help_text += ("• Type 'status' to check my health\n"
                      "• Type 'help' to see this message")

        return help_text

    # Check if agent is ready
    if not agent_executor:
        logging.warning(f"Agent not ready for user {user_id} in room {room_id}")
        return "🔄 I'm still starting up. Please try again in a moment."

    try:
        logging.info(f"Processing query from user {user_id} in room {room_id}: {user_query[:100]}...")

        # Add session context if available
        context = get_session_context(user_id) if user_id else ""
        enhanced_query = f"{context}\n\nCurrent question: {user_query}" if context else user_query

        if hasattr(agent_executor, 'invoke'):
            response = agent_executor.invoke({"input": enhanced_query})
            result = response.get("output", "I tried to find an answer but encountered an issue.")

            # Format response for chat
            formatted_result = format_for_chat(result)

            # Add to session history
            if user_id:
                add_to_session(user_id, user_query, formatted_result)

            logging.info(f"Response sent to user {user_id}: {len(formatted_result)} characters")
            return formatted_result
        else:
            return "⚠️ The agent executor is not properly configured."

    except Exception as e:
        logging.error(f"Error processing query for user {user_id}: {e}", exc_info=True)

        # Provide helpful error message based on error type
        if "connection" in str(e).lower():
            return "🔌 I'm having trouble connecting to my AI models. Please try again in a moment."
        elif "timeout" in str(e).lower():
            return "⏱️ The request took too long to process. Please try a simpler query."
        else:
            return "❌ I encountered an error processing your request. Please try rephrasing your question or try again later."


# --- Main Execution ---
if __name__ == "__main__":
    print("🚀 Initializing RAG Agent with CrowdStrike integration for direct testing...")

    success = initialize_model_and_agent()
    if not success:
        print("❌ Failed to initialize. Please check your Ollama installation and models.")
        exit(1)

    # Warm up the model
    if not warmup():
        print("⚠️  Model warmup had issues, but continuing...")

    if agent_executor:
        print("\n🧪 Testing Agent (RAG, Tools, and CrowdStrike)")
        print("=" * 60)

        test_queries = [
            "What is the main policy regarding remote work?",  # RAG test
            "What's the weather like in London?",  # Weather tool
            "Calculate (100 / 4) + 51",  # Math tool
            "Get data from https://httpbin.org/get",  # API tool
            "What is the containment status of ABC12345?",  # CrowdStrike containment test
            "Check the online status of XYZ98765",  # CrowdStrike online test
            "Get device details for TEST12345",  # CrowdStrike details test
            "What is the capital of France?",  # General knowledge
            "status"  # Health check
        ]

        for i, query in enumerate(test_queries, 1):
            print(f"\n{i}. Q: {query}")
            print("-" * 30)
            answer = ask(query, user_id="test_user", room_id="test_room")
            print(f"A: {answer}")
            print()
    else:
        print("\n❌ Agent executor not initialized. Skipping tests.")
        print("Please ensure:")
        print("• Ollama is running")
        print("• Models 'qwen2.5:14b' and 'nomic-embed-text' are available")
        print("• CrowdStrike credentials are properly configured")
        print("• Check the logs above for specific errors")
