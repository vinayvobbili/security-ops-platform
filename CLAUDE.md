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
