# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Development Commands

### Running the Application

- **Web Dashboard**: `python web/web_server.py` - Starts Flask web server with security operations dashboard
- **Streamlit Demo**: `python streamlit_app.py` - Simple Streamlit demo app
- **Webex Bots**: Various bots in `webex_bots/` directory, each can be run individually

### Bot Management (Pokedex SOC Bot)

- **Run Bot**: `./src/pokedex/run_pokedex.sh` - Start the main SOC bot
- **Restart Bot**: `./src/pokedex/restart_pokedex.sh` - Restart bot service
- **Check Status**: `./src/pokedex/pokedex_status.sh` - Check bot health
- **Kill Bot**: `./src/pokedex/kill_pokedex.sh` - Stop bot completely
- **Install Preloader**: `./src/pokedex/install_preloader_service.sh` - Install boot-time preloader service

### Testing

- **Run Tests**: `python -m pytest tests/` - Execute test suite
- **Test Specific Module**: `python -m pytest tests/test_helper_methods.py`

### Dependencies

- **Install**: `pip install -r requirements.txt`

## Project Architecture

### Core Structure

- **`src/`** - Main application logic divided into specialized modules:
    - `charts/` - Metrics visualization (aging tickets, CrowdStrike efficacy, threat analysis)
    - `components/` - Reusable business logic components (SLA monitoring, ticket management)
    - `epp/` - Endpoint Protection Platform integrations and host tagging
    - `pokedex/` - SOC Bot implementation with LLM agent architecture
    - `utils/` - Shared utilities for logging, filesystem, and HTTP operations

- **`services/`** - External platform integrations:
    - `crowdstrike.py` - CrowdStrike Falcon API integration
    - `service_now.py` - ServiceNow ticketing system
    - `tanium.py` - Tanium endpoint management
    - `webex.py` - Webex Teams communication
    - `xsoar.py` - XSOAR SOAR platform integration

- **`web/`** - Flask web application with security operations dashboard
- **`webex_bots/`** - Multiple specialized chatbots (Pokedex, Jarvais, Barnacles, etc.)
- **`data/`** - Configuration data, metrics, and transient storage

### Configuration Management

- **`my_config.py`** - Central configuration using environment variables from `data/transient/.env`
- Supports multiple environments and extensive API integrations
- Configuration includes Webex, XSOAR, CrowdStrike, ServiceNow, and other security tools

### Key Components

#### SOC Bot (Pokedex)

- LLM-powered agent with document search and tool integration
- Preloader service for instant responses (<1 second vs 30+ second cold start)
- CrowdStrike tools, weather tools, and document search capabilities
- WebEx integration for SOC analyst interactions

#### Security Operations Dashboard

- Flask-based web interface at `web/web_server.py`
- Metrics visualization, ticket management, and operational forms
- Chart generation and historical data tracking in `web/static/charts/`

#### Endpoint Protection Platform (EPP)

- Host tagging and ring management for CrowdStrike and Tanium
- Automated compliance checking and reporting
- Ring tag validation and overnight monitoring

#### Data Processing Pipeline

- Pandas/NumPy-based data analysis in `src/charts/`
- Automated report generation with timestamped outputs
- Integration with multiple security data sources

### Important Files

- **`my_config.py`** - Central configuration hub
- **`src/helper_methods.py`** - Core utilities (being refactored to `src/utils/`)
- **`web/web_server.py`** - Main web application entry point
- **`webex_bots/pokedex.py`** - Primary SOC bot implementation
- **`requirements.txt`** - Python dependencies including security tools and LLM frameworks

### Development Notes

- Environment variables loaded from `data/transient/.env`
- Logging configured for operations with rotating file handlers
- Web dashboard includes proxy functionality and security request filtering
- Bot architecture uses synchronous processing with agent-driven intelligence
- Chart generation automated with daily timestamped directories
- Configuration supports multiple Webex rooms for different operational contexts

### Security Integrations

The project integrates with enterprise security tools:

- **CrowdStrike Falcon** - Endpoint detection and response
- **Tanium** - Endpoint management and compliance
- **ServiceNow** - IT service management and ticketing
- **XSOAR** - Security orchestration and automated response
- **Webex Teams** - Secure communications and bot interactions

## Coding Guidelines

- Keep it simple and concise
- Follow SOLID principles and Clean Code practices
- All my code runs in a trusted environment, so no need of excessive defensive coding. Only exception is Pokédex.py which must be protected against prompt injection
- Git stage code files

## Architecture Principles

### Simplicity Over Complexity
- **Prefer native solutions** over custom implementations
- **Avoid over-engineering** - no special cases, detection logic, or complex abstractions
- **Trust the LLM** - let it make intelligent decisions rather than forcing behaviors
- **Clean separation** - tools do their job, LLM composes responses, presentation layer renders

### LLM Integration Philosophy
- **Single-call tool execution** - let LLM handle entire tool calling flow internally
- **Use native tool calling** (`llm.bind_tools()`) instead of manual action parsing
- **No manual tool orchestration** - avoid separate invoke() calls for tool results
- **No regex parsing** of LLM responses (Action:, Action Input:, etc.)
- **No agent frameworks** - direct LLM invocation handles everything
- **Simple system prompts** - give context, let LLM decide execution
- **Pass-through responses** - forward LLM output directly without transformation

### Tool Design
- **Tools return data** - let LLM format for user consumption
- **Use @tool decorators** directly instead of factory patterns or manager classes
- **Avoid unnecessary abstraction** - if a manager class adds no value, remove it
- **Keep tool descriptions concise** - trust domain experts (SOC analysts) to understand their tools

### Anti-Patterns to Avoid
- **Manual tool orchestration** - separate invoke() calls to handle tool results
- **Manual action parsing** with regex (`Action:`, `Action Input:`)
- **Agent frameworks** and AgentExecutor complexity
- **Special case handling** for different response formats
- **Complex detection logic** for structured data (adaptive cards, JSON)
- **Over-engineered managers** when simple functions suffice
- **Forcing LLM behavior** through complex prompts or post-processing

### Example: Clean Tool Integration
```python
# ✅ Good - Simple and direct
@tool
def get_weather(city: str) -> str:
    """Get current weather for a city."""
    response = requests.get(api_url, params={'q': city})
    return response.text

# ❌ Bad - Over-engineered
class WeatherToolsManager:
    def get_weather_tool(self):
        def weather_factory():
            # Complex factory logic...
```

### Example: Clean LLM Integration
```python
# ✅ Good - Single call with native tool calling
llm_with_tools = llm.bind_tools([weather_tool, staffing_tool])
response = llm_with_tools.invoke([
    {"role": "system", "content": "You are an assistant..."},
    {"role": "user", "content": "What's the weather?"}
])
return response.content  # LLM handles tools internally

# ❌ Bad - Manual tool orchestration
response = llm_with_tools.invoke(messages)
if response.tool_calls:
    for tool_call in response.tool_calls:
        result = execute_tool(tool_call)
        final_response = llm.invoke([original, response, tool_result])

# ❌ Bad - Manual parsing
if "Action:" in response:
    action = regex_parse_action(response)
    result = execute_tool_manually(action)
```
