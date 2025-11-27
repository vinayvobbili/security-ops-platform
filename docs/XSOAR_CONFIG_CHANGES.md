# XSOAR Configuration Improvements

## Summary

Made the XSOAR connection pool size dynamically dependent on worker count. Now you only need to change one value (`XsoarConfig.MAX_WORKERS`) and both the connection pool and parallel workers adjust automatically.

## Changes Made

### 1. Created Shared Configuration Module

**New file:** `src/config/xsoar_config.py`

```python
class XsoarConfig:
    """Global configuration for XSOAR API operations."""

    MAX_WORKERS = 10  # Change this value to adjust both workers and pool size
    POOL_SIZE_BUFFER = 5

    @classmethod
    def get_pool_size(cls) -> int:
        """Calculate connection pool size based on worker count."""
        return cls.MAX_WORKERS + cls.POOL_SIZE_BUFFER
```

### 2. Updated Connection Pool Configuration

**Modified file:** `services/xsoar.py`

- Removed hardcoded pool size (was 15)
- Now imports `XsoarConfig` and calculates pool size dynamically
- Pool size = `MAX_WORKERS + 5` buffer (default: 15)

**Before:**
```python
kwargs['maxsize'] = 15  # Hardcoded
```

**After:**
```python
from src.config import XsoarConfig
CONNECTION_POOL_SIZE = XsoarConfig.get_pool_size()  # Dynamic
kwargs['maxsize'] = CONNECTION_POOL_SIZE
```

### 3. Updated Export Configuration

**Modified file:** `src/components/web/meaningful_metrics_handler.py`

- Replaced local `MAX_WORKERS` with references to `XsoarConfig.MAX_WORKERS`
- All export and enrichment functions now use the shared configuration
- Removed environment variable dependency

**Before:**
```python
class ExportConfig:
    MAX_WORKERS = 10  # Separate from connection pool config
```

**After:**
```python
# Throughout the code, now uses:
XsoarConfig.MAX_WORKERS  # Single source of truth
```

## How to Use

### Changing Worker Count

Simply update the shared configuration:

```python
from src.config import XsoarConfig

# Change worker count (default: 10)
XsoarConfig.MAX_WORKERS = 15

# Connection pool automatically becomes 20 (15 + 5)
# All export operations automatically use 15 workers
```

### Testing the Configuration

Run the test script:

```bash
python3 test_xsoar_config.py
```

This demonstrates:
- Default configuration (10 workers → 15 pool size)
- Updated configuration (20 workers → 25 pool size)
- Automatic pool size calculation

## Benefits

1. **Single Source of Truth**: Change `XsoarConfig.MAX_WORKERS` once, everything adjusts
2. **No More Mismatches**: Pool size always matches worker count + buffer
3. **Easier Maintenance**: No need to update multiple places when tuning performance
4. **Type-Safe**: No environment variable parsing, pure Python class attributes
5. **Better Documentation**: Clear relationship between workers and pool size

## Files Modified

1. ✅ `src/config/xsoar_config.py` (NEW)
2. ✅ `src/config/__init__.py` (NEW)
3. ✅ `services/xsoar.py` (MODIFIED)
4. ✅ `src/components/web/meaningful_metrics_handler.py` (MODIFIED)
5. ✅ `test_xsoar_config.py` (NEW - demonstration)

## Performance Tuning Guide

| Worker Count | Pool Size | Use Case |
|-------------|-----------|----------|
| 5 | 10 | Conservative (low API load) |
| 10 | 15 | **Default** (balanced) |
| 15 | 20 | Aggressive (fast exports, may hit rate limits) |
| 20 | 25 | Maximum (requires careful monitoring) |

**Note:** API rate limiting typically occurs above 10-15 concurrent requests.

## Migration Notes

No code changes needed for existing functionality. The default value (10 workers) remains the same. To adjust performance:

```python
# In your startup code or config file
from src.config import XsoarConfig

# Tune based on your needs
XsoarConfig.MAX_WORKERS = 12  # Example: slightly more aggressive
```

## Related Issues Fixed

1. ✅ Missing `TIMEOUT_PER_TICKET` constant in `ExportConfig` (was referenced but not defined)
2. ✅ Removed unused `last_progress_time` variable
3. ✅ Connection pool size now properly synchronized with worker count
