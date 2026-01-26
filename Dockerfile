# Security Operations Platform - Docker Image
# Multi-stage build for optimized production image

# =============================================================================
# Stage 1: Builder
# =============================================================================
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Stage 2: Production
# =============================================================================
FROM python:3.11-slim as production

# Labels for container metadata
LABEL maintainer="Vinay Vobbilichetty"
LABEL description="Security Operations Automation Platform"
LABEL version="1.0.0"

# Security: Run as non-root user
RUN groupadd -r iruser && useradd -r -g iruser iruser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=iruser:iruser . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data/transient && \
    chown -R iruser:iruser /app/logs /app/data

# Environment configuration
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOG_LEVEL=INFO

# Switch to non-root user
USER iruser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/health', timeout=5)" || exit 1

# Default port for web server
EXPOSE 5000

# Default command: start web server
CMD ["python", "web/web_server.py"]

# =============================================================================
# Stage 3: Development (optional)
# =============================================================================
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-asyncio \
    black \
    flake8 \
    mypy \
    ipython

USER iruser

# Override command for development
CMD ["python", "-m", "pytest", "tests/", "-v"]
