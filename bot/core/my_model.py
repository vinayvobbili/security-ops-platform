# /services/my_model.py
"""
Simple Security Operations RAG Bot

Core functionality:
- Initialize Ollama LLM with documents and tools
- Process user messages and return responses for Webex

Created for Acme Security Operations
"""
import logging
import time
from bot.core.state_manager import get_state_manager

logging.basicConfig(level=logging.INFO)


def initialize_model_and_agent():
    """Initialize the LLM, embeddings, and agent"""
    state_manager = get_state_manager()
    success = state_manager.initialize_all_components()

    if success:
        logging.info("SecurityBot initialized successfully")
    else:
        logging.error("SecurityBot initialization failed")

    return success


def ask(user_message: str) -> str:
    """
    SOC Q&A function following requirements from Pokédex.py:
    1. Search documents first
    2. Use tools as needed
    3. Supplement with LLM (with disclaimers)
    4. Provide source attribution
    """
    import os
    from langchain_ollama import ChatOllama, OllamaEmbeddings
    from langchain_community.vectorstores import FAISS
    from bot.utils.enhanced_config import ModelConfig

    start_time = time.time()

    try:
        # Basic validation
        if not user_message or not user_message.strip():
            return "Please ask me a question!"

        query = user_message.strip()

        # Handle simple commands
        if query.lower() in ['hello', 'hi']:
            return "👋 SOC Q&A Assistant ready - ask me anything!"
        elif query.lower() in ['status', 'health']:
            return "✅ System online and ready"
        elif query.lower() == 'help':
            return "🤖 I can search security documents and provide security guidance."

        response_parts = []
        config = ModelConfig()

        # STEP 1: Search documents first
        try:
            embeddings = OllamaEmbeddings(model=config.embedding_model_name)

            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            faiss_path = os.path.join(project_root, "faiss_index_ollama")

            if os.path.exists(faiss_path):
                document_store = FAISS.load_local(faiss_path, embeddings, allow_dangerous_deserialization=True)
                docs = document_store.similarity_search(query, k=3)

                if docs:
                    content_parts = []
                    sources = set()

                    for doc in docs:
                        if doc.page_content.strip():
                            content_parts.append(doc.page_content.strip())
                            if hasattr(doc, 'metadata') and 'source' in doc.metadata:
                                sources.add(os.path.basename(doc.metadata['source']))

                    if content_parts:
                        combined_content = "\n\n".join(content_parts)
                        source_list = ", ".join(sorted(sources)) if sources else "Local documentation"

                        # Clean and format the documentation content
                        formatted_content = f"📋 **From Local Documentation:**\n\n{combined_content}\n\n**Source:** {source_list}"
                        response_parts.append(formatted_content)
                        logging.info(f"Found docs: {source_list}")
        except Exception as e:
            logging.warning(f"Document search failed: {e}")

        # STEP 2: Basic tool check
        query_lower = query.lower()
        if any(word in query_lower for word in ['weather', 'temperature']):
            response_parts.append("🌤️ **Weather Info:** Please specify a location for weather information.")
        elif any(word in query_lower for word in ['device', 'host', 'crowdstrike']):
            response_parts.append("🛡️ **Security Tools:** Please specify device/host for detailed information.")

        # STEP 3: LLM supplementation
        try:
            llm = ChatOllama(model=config.llm_model_name, temperature=config.temperature)

            # Always provide LLM response - let it handle context appropriately
            if response_parts:  # Has document content
                llm_prompt = f'Based on this security documentation, provide 1-2 sentences of key actionable guidance for a SOC analyst. Be very concise.'
            else:  # No documents found
                llm_prompt = f'A SOC analyst asked: "{query}". If this is a security question, provide 1-2 sentences of practical guidance. If it\'s a test/casual question, respond appropriately for a SOC bot. Be very concise.'

            response = llm.invoke(llm_prompt)
            llm_content = response.content.strip() if hasattr(response, 'content') else str(response).strip()

            if llm_content and len(llm_content) < 300:  # Keep it short
                disclaimer = "⚠️ **General Security Guidance**"
                supplemental = f"{disclaimer}\n\n{llm_content}"
                response_parts.append(supplemental)

        except Exception as e:
            logging.warning(f"LLM supplementation failed: {e}")

        # Return combined response
        if response_parts:
            final_response = "\n\n---\n\n".join(response_parts)
        else:
            final_response = "❌ No information found. Please rephrase or contact your security team."

        elapsed = time.time() - start_time
        if elapsed > 25:
            logging.warning(f"Response took {elapsed:.1f}s")

        return final_response

    except Exception as e:
        logging.error(f"Ask function failed: {e}")
        return "❌ An error occurred. Please try again or contact support."


