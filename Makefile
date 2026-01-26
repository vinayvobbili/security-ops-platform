# Security Operations Platform - Makefile
# Common development and deployment commands

.PHONY: help install install-dev test lint format security clean docker-build docker-run web bot

# Default target
help:
	@echo "Security Operations Platform - Available Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install       Install production dependencies"
	@echo "  make install-dev   Install development dependencies"
	@echo "  make setup         Full development setup"
	@echo ""
	@echo "Development:"
	@echo "  make test          Run test suite"
	@echo "  make test-cov      Run tests with coverage report"
	@echo "  make lint          Run all linters"
	@echo "  make format        Format code with black and isort"
	@echo "  make security      Run security scans (bandit)"
	@echo "  make check         Run all checks (lint + test + security)"
	@echo ""
	@echo "Running:"
	@echo "  make web           Start web dashboard"
	@echo "  make bot           Start pokedex bot"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-run    Run Docker container"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean         Remove build artifacts and cache"
	@echo "  make clean-all     Remove all generated files including venv"

# =============================================================================
# Setup
# =============================================================================

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install pytest pytest-cov pytest-asyncio pytest-mock
	pip install black isort flake8 mypy bandit pre-commit
	pre-commit install || true

setup: install-dev
	@echo "Development environment ready!"

# =============================================================================
# Development
# =============================================================================

test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --cov=services --cov=my_bot --cov=src --cov-report=term-missing --cov-report=html
	@echo "Coverage report: htmlcov/index.html"

test-fast:
	pytest tests/ -v -x --tb=short -m "not slow"

lint:
	@echo "Running flake8..."
	flake8 services/ my_bot/ src/ web/ --max-line-length=120 --ignore=E501,W503
	@echo "Running mypy..."
	mypy services/ my_bot/ src/ --ignore-missing-imports || true
	@echo "Checking black formatting..."
	black --check --diff services/ my_bot/ src/ web/ || true
	@echo "Checking import sorting..."
	isort --check-only --diff services/ my_bot/ src/ web/ || true

format:
	@echo "Formatting with black..."
	black services/ my_bot/ src/ web/ webex_bots/
	@echo "Sorting imports with isort..."
	isort services/ my_bot/ src/ web/ webex_bots/

security:
	@echo "Running bandit security scan..."
	bandit -r services/ my_bot/ src/ web/ -ll -ii -x tests
	@echo "Checking dependencies for vulnerabilities..."
	pip-audit || safety check -r requirements.txt || true

check: lint test security
	@echo "All checks passed!"

# =============================================================================
# Running
# =============================================================================

web:
	python web/web_server.py

bot:
	python webex_bots/pokedex.py

bot-hal:
	python webex_bots/hal9000.py

# =============================================================================
# Docker
# =============================================================================

docker-build:
	docker build -t security-ops-platform:latest .

docker-run:
	docker run -d -p 5000:5000 --env-file .env --name secops security-ops-platform:latest

docker-stop:
	docker stop secops || true
	docker rm secops || true

docker-logs:
	docker logs -f secops

# =============================================================================
# Maintenance
# =============================================================================

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .coverage coverage.xml
	@echo "Cleaned build artifacts"

clean-all: clean
	rm -rf .venv venv
	@echo "Cleaned everything including virtual environment"

# =============================================================================
# Utilities
# =============================================================================

deps-check:
	@echo "Checking for outdated dependencies..."
	pip list --outdated

deps-tree:
	@echo "Dependency tree:"
	pip install pipdeptree 2>/dev/null || true
	pipdeptree

loc:
	@echo "Lines of code:"
	@find services my_bot src web webex_bots -name "*.py" | xargs wc -l | tail -1
