# 🛡️ The Whole Truth - Security Operations Automation Platform

A comprehensive, enterprise-grade security operations automation platform that integrates incident response workflows, threat intelligence, asset management, and team collaboration across multiple security tools and platforms.

## 🌟 Overview

This platform automates and orchestrates security operations workflows, providing a unified interface for incident response, threat hunting, asset enrichment, and team collaboration. It eliminates manual toil, reduces response times, and ensures consistent execution of security processes.

## ✨ Key Features

### 🤖 Intelligent Automation Bots
- **Multi-platform chat bots** - Interactive Webex bots for security operations
- **Self-healing architecture** - Automatic recovery from network disruptions and API failures
- **Concurrent processing** - Handle multiple incidents simultaneously with optimized performance
- **Natural language commands** - Execute security workflows through conversational interfaces

### 🎯 Incident Response Orchestration
- **XSOAR/Cortex Integration** - Automated ticket management, enrichment, and workflow execution
- **ServiceNow Integration** - Bidirectional sync, automated ticket creation, and asset correlation
- **Automated Triage** - Intelligent ticket classification, prioritization, and routing
- **Countdown Timers** - SLA tracking and automated escalation for time-sensitive incidents

### 📊 Asset Intelligence & Enrichment
- **Multi-source Enrichment** - Correlate data from ServiceNow, Tanium, CrowdStrike, and Active Directory
- **Automated Tagging** - Dynamic asset classification and ring assignment
- **Real-time Asset Discovery** - Continuous monitoring and inventory updates
- **Geo-distributed Assets** - Support for global infrastructure with regional mapping

### 📈 Security Metrics & Dashboards
- **Real-time Dashboards** - Interactive web-based metrics and KPIs
- **Ticket Aging Analytics** - Track incident lifecycle and bottlenecks
- **Volume Trending** - Identify patterns and capacity planning insights
- **Custom Reporting** - Exportable reports with timestamped data

### 🔗 Platform Integrations
- **XSOAR (Cortex)** - Full API integration for incident management
- **ServiceNow** - CMDB, incident, and change management
- **Tanium** - Endpoint visibility and management
- **CrowdStrike** - EDR telemetry and threat intelligence
- **Azure DevOps** - Work item tracking and automation
- **Webex** - Team collaboration and notifications
- **Email (OAuth2)** - Secure email automation with Microsoft 365

### 🚀 Advanced Capabilities
- **Resilient Architecture** - Automatic reconnection, retry logic, and circuit breakers
- **Configuration as Code** - Centralized configuration management
- **Batch Processing** - Efficient bulk operations with progress tracking
- **Error Recovery** - Graceful degradation and detailed error reporting
- **Session Management** - Stateful workflows with persistent context
- **API Rate Limiting** - Intelligent throttling and quota management

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Dashboard (Flask)                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Metrics  │  │ Tickets  │  │ Assets   │  │ Reports  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────┼─────────────────────────────┐
│                    Core Automation Layer                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Webex    │  │ XSOAR    │  │ Ticket   │  │ Asset    │   │
│  │ Bots     │  │ Client   │  │ Cache    │  │ Enricher │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────┼─────────────────────────────┐
│                    Service Integration Layer                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ServiceNow│  │ Tanium   │  │CrowdStrike│  │ Azure    │   │
│  │          │  │          │  │           │  │ DevOps   │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
.
├── src/                    # Core application logic
│   ├── components/         # Reusable components (ticket cache, enrichment)
│   ├── charts/            # Metrics and visualization logic
│   └── utils/             # Shared utilities and helpers
├── services/              # External service integrations
│   ├── xsoar/            # XSOAR/Cortex client and handlers
│   ├── service_now.py    # ServiceNow API client
│   ├── tanium.py         # Tanium integration
│   └── crowdstrike.py    # CrowdStrike Falcon API
├── webex_bots/           # Webex bot implementations
│   ├── pokedex.py        # Primary security operations bot
│   ├── toodles.py        # Collaboration and notification bot
│   └── msoar.py          # XSOAR-integrated bot
├── web/                  # Web dashboard
│   ├── templates/        # HTML templates
│   ├── static/          # CSS, JavaScript, assets
│   └── app.py    # Flask application
├── data/                # Data files and mappings
├── startup_scripts/     # Bot deployment scripts
├── deployment/          # Infrastructure and deployment configs
└── tests/              # Test suite

```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Access to required services (XSOAR, ServiceNow, Tanium, etc.)
- API credentials for integrated platforms

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd The_Whole_Truth

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. **Copy the sample environment file:**
   ```bash
   cp .env.sample .env
   ```

2. **Edit `my_config.py` with your settings:**
   - API endpoints and credentials
   - Team-specific configuration
   - Feature flags and customizations

3. **Configure service integrations:**
   - XSOAR: API key, base URL, verify SSL
   - ServiceNow: Instance URL, credentials
   - Tanium: On-prem/cloud endpoints, tokens
   - CrowdStrike: Client ID, secret

### Running the Platform

#### Start the Web Dashboard
```bash
python web/app.py
```
Access at `http://localhost:5000`

#### Launch Webex Bots
```bash
# Start all bots
./startup_scripts/start_scheduler.sh

# Or start individual bots
python webex_bots/pokedex.py
python webex_bots/toodles.py
```

#### Run Asset Enrichment
```bash
python src/components/asset_enrichment.py
```

## 🎯 Use Cases

### 1️⃣ Automated Incident Response
- Automatically enrich security alerts with asset context
- Correlate indicators across multiple security tools
- Execute response playbooks through XSOAR integration
- Track incident SLAs with countdown timers

### 2️⃣ Asset Management Automation
- Sync asset inventory across CMDB, Tanium, and CrowdStrike
- Automated tagging and classification (ring assignments)
- Geographic and organizational asset mapping
- Compliance reporting and asset tracking

### 3️⃣ Security Operations Workflows
- Ticket routing and assignment automation
- Batch processing of security events
- Automated employee outreach for security incidents
- Integration with DevOps workflows

### 4️⃣ Team Collaboration
- Real-time notifications via Webex
- Interactive bot commands for common operations
- Shared dashboards and metrics
- Collaborative incident investigation

## 🔧 Key Components

### Ticket Cache System
High-performance caching layer for XSOAR tickets with:
- Batch synchronization and incremental updates
- Multi-threaded processing for performance
- Automatic retry on failure
- Enrichment pipeline integration

### Asset Enrichment Engine
Multi-source asset correlation:
- ServiceNow CMDB data
- Tanium endpoint telemetry
- CrowdStrike threat intelligence
- Active Directory attributes

### Webex Bot Framework
Resilient bot architecture:
- WebSocket-based real-time communication
- Automatic reconnection on network failures
- Command parsing and natural language understanding
- Role-based access control

### Metrics & Analytics
Real-time operational metrics:
- Ticket aging and SLA tracking
- Volume trends and forecasting
- Team performance metrics
- Custom KPI dashboards

## 📚 Documentation

- **[AGENTS.md](docs/AGENTS.md)** - AI assistant integration guide
- **[CLAUDE.md](CLAUDE.md)** - Claude Code usage instructions

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Guidelines
- Follow existing code structure and patterns
- Add tests for new functionality
- Update documentation for significant changes
- Use descriptive commit messages

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**TL;DR:** You can use, modify, and distribute this code freely. Just keep the copyright notice.

## 🙏 Acknowledgments

Built with modern Python best practices and enterprise-grade reliability in mind. Designed to scale from small teams to large security operations centers.

---

**Note:** This platform requires valid credentials and access to the integrated services. Refer to individual service documentation for setup requirements.
