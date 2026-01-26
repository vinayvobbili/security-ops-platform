# Contributing to Security Operations Platform

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)

### Local Development

```bash
# Clone the repository
git clone https://github.com/vinayvobbili/My_Whole_Truth.git
cd My_Whole_Truth

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=src --cov=services --cov-report=term-missing

# Run specific test file
pytest tests/test_services.py -v

# Run tests matching a pattern
pytest tests/ -v -k "test_token"
```

### Code Quality

```bash
# Format code with Black
black src/ services/ webex_bots/ my_bot/

# Check linting with flake8
flake8 src/ services/ --max-line-length=120

# Type checking with mypy
mypy src/ services/ --ignore-missing-imports
```

## Code Style Guidelines

### Python Style

- Follow PEP 8 with a maximum line length of 120 characters
- Use type hints for function signatures
- Write docstrings for public functions and classes
- Use meaningful variable and function names

### Example

```python
def enrich_incident(
    incident_id: str,
    include_assets: bool = True,
    timeout: float = 30.0
) -> dict:
    """
    Enrich an incident with additional context from multiple sources.

    Args:
        incident_id: The unique identifier of the incident
        include_assets: Whether to include asset information
        timeout: Maximum time to wait for enrichment in seconds

    Returns:
        Dictionary containing enriched incident data

    Raises:
        ValueError: If incident_id is invalid
        TimeoutError: If enrichment exceeds timeout
    """
    pass
```

### Commit Messages

Use conventional commit format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(enrichment): add CrowdStrike threat intelligence integration
fix(token): handle token refresh race condition
docs(readme): update installation instructions
test(services): add ServiceNow client unit tests
```

## Pull Request Process

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the style guidelines

3. **Write tests** for new functionality

4. **Run the test suite** to ensure nothing is broken:
   ```bash
   pytest tests/ -v
   ```

5. **Update documentation** if needed

6. **Submit a pull request** with:
   - Clear description of changes
   - Reference to any related issues
   - Screenshots for UI changes (if applicable)

## Project Structure

```
.
├── src/                 # Core application logic
│   ├── components/      # Business logic components
│   ├── charts/          # Metrics visualization
│   └── utils/           # Shared utilities
├── services/            # External API integrations
├── webex_bots/          # Webex bot implementations
├── my_bot/              # LLM-powered assistant
├── web/                 # Flask web application
├── tests/               # Test suite
├── deployment/          # Deployment configurations
└── docs/                # Documentation
```

## Adding New Integrations

When adding a new service integration:

1. Create a new file in `services/`
2. Follow the existing client pattern (authentication, error handling, retry logic)
3. Add corresponding tests in `tests/test_services.py`
4. Update documentation if the integration is user-facing

### Service Client Template

```python
"""
Service Name API Client

Provides integration with Service Name for [purpose].
"""

import logging
from typing import Optional, Dict, Any

import requests
from requests.adapters import HTTPAdapter

from my_config import get_config
from src.utils.http_utils import get_session

logger = logging.getLogger(__name__)
config = get_config()


class ServiceNameClient:
    """Client for Service Name API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None
    ):
        self.base_url = base_url or config.api.service_name_url
        self.api_key = api_key or config.api.service_name_key
        self.session = get_session()

    def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Make authenticated API request."""
        url = f"{self.base_url}/{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        response = self.session.request(
            method,
            url,
            headers=headers,
            **kwargs
        )
        response.raise_for_status()
        return response.json()
```

## Questions?

If you have questions about contributing, feel free to:
- Open an issue for discussion
- Reach out via the project's communication channels

Thank you for contributing!
