"""Shared XSOAR configuration for connection pooling and parallel operations.

This module provides centralized configuration for XSOAR API client settings,
particularly for connection pooling and parallel worker management.
"""


class XsoarConfig:
    """Global configuration for XSOAR API operations."""

    # Worker count for parallel API operations (export, enrichment, etc.)
    # This determines both ThreadPoolExecutor worker count and connection pool size
    # API rate limiting occurs above 10-15 concurrent requests
    # Default: 10 (balanced throughput without overwhelming API)
    MAX_WORKERS = 20

    # Connection pool size is calculated as MAX_WORKERS + buffer
    # Buffer accounts for connection cleanup, timeouts, and retries
    POOL_SIZE_BUFFER = 5

    @classmethod
    def get_pool_size(cls) -> int:
        """Calculate connection pool size based on worker count.

        Returns:
            Connection pool size (MAX_WORKERS + POOL_SIZE_BUFFER)
        """
        return cls.MAX_WORKERS + cls.POOL_SIZE_BUFFER
