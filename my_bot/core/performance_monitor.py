# /my_bot/core/performance_monitor.py
"""
Performance Monitor for Security Bot

Tracks actual bot usage metrics including:
- Unique users
- Concurrent users  
- Total queries
- Response times
- System resources
"""

import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, Set, LiteralString
import psutil


class PerformanceMonitor:
    """Thread-safe performance monitoring for the bot"""

    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()

        # User tracking
        self.unique_users: Set[str] = set()
        self.concurrent_users: Set[str] = set()
        self.peak_concurrent_users = 0

        # Query tracking
        self.total_queries = 0
        self.queries_24h = 0
        self.last_24h_reset = time.time()

        # Response time tracking
        self.response_times = []
        self.max_response_times = 1000  # Keep last 1000 response times

        # Error tracking
        self.total_errors = 0

        # Active sessions (user -> last_activity_time)
        self.active_sessions: Dict[str, float] = {}
        self.session_timeout = 300  # 5 minutes

        # Data persistence
        self.data_file = Path("performance_data.json")
        self.load_persistent_data()

    def record_query(self, user_id: str, response_time: float = None, error: bool = False):
        """Record a query from a user"""
        with self.lock:
            current_time = time.time()

            # Track user
            self.unique_users.add(user_id)
            self.concurrent_users.add(user_id)
            self.active_sessions[user_id] = current_time

            # Update peak concurrent users
            if len(self.concurrent_users) > self.peak_concurrent_users:
                self.peak_concurrent_users = len(self.concurrent_users)

            # Track query
            self.total_queries += 1

            # Reset 24h counter if needed
            if current_time - self.last_24h_reset > 86400:  # 24 hours
                self.queries_24h = 0
                self.last_24h_reset = current_time
            self.queries_24h += 1

            # Track response time
            if response_time is not None:
                self.response_times.append(response_time)
                if len(self.response_times) > self.max_response_times:
                    self.response_times.pop(0)

            # Track errors
            if error:
                self.total_errors += 1

            # Clean up old sessions
            self._cleanup_old_sessions()

    def end_user_session(self, user_id: str):
        """Mark user session as ended"""
        with self.lock:
            self.concurrent_users.discard(user_id)
            self.active_sessions.pop(user_id, None)

    def _cleanup_old_sessions(self):
        """Remove sessions that have been inactive for too long"""
        current_time = time.time()
        expired_users = []

        for user_id, last_activity in self.active_sessions.items():
            if current_time - last_activity > self.session_timeout:
                expired_users.append(user_id)

        for user_id in expired_users:
            self.concurrent_users.discard(user_id)
            del self.active_sessions[user_id]

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        with self.lock:
            self._cleanup_old_sessions()

            # Calculate average response time
            avg_response_time = 0.0
            if self.response_times:
                avg_response_time = sum(self.response_times) / len(self.response_times)

            # Get system stats
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent()
            process = psutil.Process()

            # Calculate uptime
            uptime_seconds = time.time() - self.start_time
            uptime_hours = uptime_seconds / 3600

            return {
                'concurrent_users': len(self.concurrent_users),
                'peak_concurrent_users': self.peak_concurrent_users,
                'unique_users_total': len(self.unique_users),
                'avg_response_time_seconds': round(avg_response_time, 2),
                'total_queries_24h': self.queries_24h,
                'total_lifetime_queries': self.total_queries,
                'total_errors': self.total_errors,
                'uptime_hours': round(uptime_hours, 1),
                'active_sessions': len(self.active_sessions),
                'system': {
                    'memory_percent': memory.percent,
                    'memory_available_gb': round(memory.available / (1024 ** 3), 2),
                    'cpu_percent': cpu_percent,
                    'process_memory_mb': round(process.memory_info().rss / (1024 ** 2), 1)
                }
            }

    def get_capacity_warning(self) -> LiteralString | None:
        """Check for capacity warnings"""
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent()

        warnings = []
        if memory.percent > 85:
            warnings.append(f"High memory usage: {memory.percent}%")
        if cpu_percent > 80:
            warnings.append(f"High CPU usage: {cpu_percent}%")
        if len(self.concurrent_users) > 50:
            warnings.append(f"High concurrent users: {len(self.concurrent_users)}")

        return "; ".join(warnings) if warnings else None

    def save_persistent_data(self):
        """Save data to disk for persistence across restarts"""
        try:
            data = {
                'unique_users': list(self.unique_users),
                'total_queries': self.total_queries,
                'peak_concurrent_users': self.peak_concurrent_users,
                'total_errors': self.total_errors,
                'start_time': self.start_time
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Error saving performance data: {e}")

    def load_persistent_data(self):
        """Load data from disk if available"""
        try:
            if self.data_file.exists():
                with open(self.data_file, 'r') as f:
                    data = json.load(f)
                    self.unique_users = set(data.get('unique_users', []))
                    self.total_queries = data.get('total_queries', 0)
                    self.peak_concurrent_users = data.get('peak_concurrent_users', 0)
                    self.total_errors = data.get('total_errors', 0)
                    # Don't restore start_time - use current session start time
        except Exception as e:
            print(f"Error loading performance data: {e}")


# Global instance
_performance_monitor = None


def get_performance_monitor() -> PerformanceMonitor:
    """Get global performance monitor instance"""
    global _performance_monitor
    if _performance_monitor is None:
        _performance_monitor = PerformanceMonitor()
    return _performance_monitor


# For backward compatibility with existing imports
performance_monitor = get_performance_monitor()


class SessionManager:
    """Simple session manager for tracking user sessions"""

    def __init__(self):
        self.performance_monitor = get_performance_monitor()

    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        perf_stats = self.performance_monitor.get_stats()
        return {
            'active_users': perf_stats['concurrent_users'],
            'total_users_ever': perf_stats['unique_users_total'],
            'total_interactions': perf_stats['total_lifetime_queries']
        }


# For backward compatibility with existing imports
session_manager = SessionManager()
