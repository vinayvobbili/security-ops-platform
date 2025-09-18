"""
Tool Decorator for Automatic Logging

Provides a decorator that automatically logs tool calls when they are invoked.
"""

import time
import functools
from typing import Any, Callable
from .tool_logging import log_tool_call as _log_tool_call

def log_tool_call(tool_func: Callable) -> Callable:
    """
    Decorator to automatically log tool calls

    Usage:
        @tool
        @log_tool_call
        def my_tool(arg1: str, arg2: int) -> str:
            return "result"
    """
    @functools.wraps(tool_func)
    def wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        tool_name = getattr(tool_func, 'name', tool_func.__name__)

        # Combine args and kwargs for logging
        input_args = {}
        if args:
            input_args['args'] = args
        if kwargs:
            input_args.update(kwargs)

        try:
            # Execute the tool
            result = tool_func(*args, **kwargs)

            # Calculate execution time
            execution_time_ms = (time.time() - start_time) * 1000

            # Log successful call
            _log_tool_call(
                tool_name=tool_name,
                input_args=input_args,
                output=result,
                execution_time_ms=execution_time_ms,
                success=True
            )

            return result

        except Exception as e:
            # Calculate execution time even for errors
            execution_time_ms = (time.time() - start_time) * 1000

            # Log failed call
            _log_tool_call(
                tool_name=tool_name,
                input_args=input_args,
                output=None,
                execution_time_ms=execution_time_ms,
                success=False,
                error_message=str(e)
            )

            # Re-raise the exception
            raise

    return wrapper