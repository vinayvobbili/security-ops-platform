# /services/performance_monitor.py
"""
Performance Monitoring Module

This module provides comprehensive performance monitoring capabilities for the
security operations bot, including metrics tracking, system resource monitoring,
and persistent data storage.
"""

import os
import logging
import json
import threading
import time
import psutil
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional


class PerformanceMonitor:
    """Thread-safe performance monitoring with persistent storage"""

    def __init__(self, max_response_time_samples: int = 1000, data_file_path: str = None):
        self._lock = threading.RLock()
        self._start_time = datetime.now()
        self._data_file = data_file_path or os.path.join(
            os.path.dirname(__file__), "..", "performance_data.json"
        )

        # Concurrent user tracking
        self._active_requests: Dict[str, datetime] = {}
        self._peak_concurrent_users = 0

        # Response time tracking
        self._response_times = deque(maxlen=max_response_time_samples)

        # Query volume tracking (hourly buckets)
        self._hourly_queries = defaultdict(int)

        # Error tracking
        self._error_count = 0
        self._last_error_time = None

        # Cache hit tracking
        self._cache_hits = 0
        self._cache_misses = 0

        # Query type tracking
        self._query_types = defaultdict(int)

        # Total lifetime stats (persistent across restarts)
        self._total_lifetime_queries = 0
        self._total_lifetime_errors = 0
        self._initial_start_time = datetime.now()

        # Load existing data if available
        self._load_persistent_data()

    def _load_persistent_data(self) -> None:
        """Load persistent performance data from file"""
        try:
            if os.path.exists(self._data_file):
                with open(self._data_file, 'r') as f:
                    data = json.load(f)

                # Restore persistent counters
                self._peak_concurrent_users = data.get('peak_concurrent_users', 0)
                self._error_count = data.get('total_errors', 0)
                self._cache_hits = data.get('cache_hits', 0)
                self._cache_misses = data.get('cache_misses', 0)
                self._total_lifetime_queries = data.get('total_lifetime_queries', 0)
                self._total_lifetime_errors = data.get('total_lifetime_errors', 0)

                # Restore query types
                if 'query_types' in data:
                    self._query_types = defaultdict(int, data['query_types'])

                # Restore recent hourly queries only
                if 'hourly_queries' in data:
                    current_time = datetime.now()
                    cutoff_time = current_time - timedelta(hours=48)
                    cutoff_hour = cutoff_time.strftime("%Y-%m-%d-%H")

                    for hour, count in data['hourly_queries'].items():
                        if hour >= cutoff_hour:
                            self._hourly_queries[hour] = count

                # Restore recent response times only
                if 'response_times' in data:
                    recent_times = data['response_times'][-200:]
                    self._response_times.extend(recent_times)

                # Restore timestamps
                if 'last_error_time' in data and data['last_error_time']:
                    self._last_error_time = datetime.fromisoformat(data['last_error_time'])

                if 'initial_start_time' in data:
                    self._initial_start_time = datetime.fromisoformat(data['initial_start_time'])

                logging.info(f"Loaded performance data: {self._total_lifetime_queries} lifetime queries, "
                             f"{self._error_count} total errors, peak {self._peak_concurrent_users} concurrent users")
            else:
                logging.info("No existing performance data found, starting fresh")

        except Exception as e:
            logging.error(f"Failed to load performance data: {e}")

    def _save_persistent_data(self) -> None:
        """Save persistent performance data to file"""
        try:
            data = {
                'peak_concurrent_users': self._peak_concurrent_users,
                'total_errors': self._error_count,
                'cache_hits': self._cache_hits,
                'cache_misses': self._cache_misses,
                'total_lifetime_queries': self._total_lifetime_queries,
                'total_lifetime_errors': self._total_lifetime_errors,
                'query_types': dict(self._query_types),
                'hourly_queries': dict(self._hourly_queries),
                'response_times': list(self._response_times),
                'last_error_time': self._last_error_time.isoformat() if self._last_error_time else None,
                'initial_start_time': self._initial_start_time.isoformat(),
                'last_save_time': datetime.now().isoformat()
            }

            # Ensure directory exists
            os.makedirs(os.path.dirname(self._data_file), exist_ok=True)

            # Write to temp file first, then move (atomic operation)
            temp_file = self._data_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)

            os.replace(temp_file, self._data_file)

        except Exception as e:
            logging.error(f"Failed to save performance data: {e}")

    def start_request(self, user_id: str, query_type: str = "general") -> None:
        """Mark the start of a request for a user"""
        with self._lock:
            current_time = datetime.now()
            self._active_requests[user_id] = current_time

            # Update peak concurrent users
            concurrent_count = len(self._active_requests)
            if concurrent_count > self._peak_concurrent_users:
                self._peak_concurrent_users = concurrent_count

            # Track query volume by hour
            hour_key = current_time.strftime("%Y-%m-%d-%H")
            self._hourly_queries[hour_key] += 1

            # Track query types
            self._query_types[query_type] += 1

            # Increment lifetime counter
            self._total_lifetime_queries += 1

            # Clean up old hourly data (keep last 48 hours)
            self._cleanup_old_hourly_data(current_time)

    def _cleanup_old_hourly_data(self, current_time: datetime) -> None:
        """Clean up old hourly data (called with lock held)"""
        cutoff_time = current_time - timedelta(hours=48)
        cutoff_hour = cutoff_time.strftime("%Y-%m-%d-%H")

        hours_to_remove = [
            hour for hour in self._hourly_queries.keys()
            if hour < cutoff_hour
        ]
        for hour in hours_to_remove:
            del self._hourly_queries[hour]

    def end_request(self, user_id: str, response_time_seconds: float, error: bool = False) -> None:
        """Mark the end of a request for a user"""
        with self._lock:
            # Remove from active requests
            if user_id in self._active_requests:
                del self._active_requests[user_id]

            # Track response time
            self._response_times.append(response_time_seconds)

            # Track errors
            if error:
                self._error_count += 1
                self._total_lifetime_errors += 1
                self._last_error_time = datetime.now()

            # Periodically save data (every 10 requests)
            if self._total_lifetime_queries % 10 == 0:
                self._save_persistent_data()

    def record_cache_hit(self) -> None:
        """Record a cache hit"""
        with self._lock:
            self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss"""
        with self._lock:
            self._cache_misses += 1

    def get_concurrent_users(self) -> int:
        """Get current number of concurrent users"""
        with self._lock:
            # Clean up stale requests (older than 5 minutes)
            current_time = datetime.now()
            stale_cutoff = current_time - timedelta(minutes=5)

            stale_users = [
                user_id for user_id, start_time in self._active_requests.items()
                if start_time < stale_cutoff
            ]

            for user_id in stale_users:
                del self._active_requests[user_id]

            return len(self._active_requests)

    def get_average_response_time(self) -> float:
        """Get average response time in seconds"""
        with self._lock:
            if not self._response_times:
                return 0.0
            return sum(self._response_times) / len(self._response_times)

    def get_memory_usage(self) -> Dict[str, float]:
        """Get current memory usage statistics"""
        try:
            process = psutil.Process()
            memory_info = process.memory_info()
            system_memory = psutil.virtual_memory()

            return {
                'process_memory_mb': memory_info.rss / 1024 / 1024,
                'process_memory_percent': process.memory_percent(),
                'system_memory_percent': system_memory.percent,
                'system_memory_available_gb': system_memory.available / 1024 / 1024 / 1024,
                'system_memory_total_gb': system_memory.total / 1024 / 1024 / 1024
            }
        except Exception as e:
            logging.error(f"Error getting memory usage: {e}")
            return {
                'process_memory_mb': 0,
                'process_memory_percent': 0,
                'system_memory_percent': 0,
                'system_memory_available_gb': 0,
                'system_memory_total_gb': 0
            }

    def get_system_stats(self) -> Dict[str, float]:
        """Get system resource statistics"""
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            disk_usage = psutil.disk_usage('/')
            disk_percent = (disk_usage.used / disk_usage.total) * 100
            disk_free_gb = disk_usage.free / 1024 / 1024 / 1024
            
            return {
                'cpu_percent': cpu_percent,
                'disk_percent': disk_percent,
                'disk_free_gb': disk_free_gb
            }
        except Exception as e:
            logging.error(f"Error getting system stats: {e}")
            return {
                'cpu_percent': 0,
                'disk_percent': 0,
                'disk_free_gb': 0
            }

    def get_queries_per_hour(self) -> Dict[str, int]:
        """Get query volume for the last 24 hours"""
        with self._lock:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=24)
            cutoff_hour = cutoff_time.strftime("%Y-%m-%d-%H")

            return {
                hour: count for hour, count in self._hourly_queries.items()
                if hour >= cutoff_hour
            }

    def get_total_queries_24h(self) -> int:
        """Get total queries in the last 24 hours"""
        queries_per_hour = self.get_queries_per_hour()
        return sum(queries_per_hour.values())

    def get_stats(self) -> Dict:
        """Get comprehensive performance statistics"""
        with self._lock:
            current_time = datetime.now()
            uptime_hours = (current_time - self._start_time).total_seconds() / 3600
            total_uptime_hours = (current_time - self._initial_start_time).total_seconds() / 3600

            memory_stats = self.get_memory_usage()
            system_stats = self.get_system_stats()

            # Calculate cache hit rate
            total_cache_operations = self._cache_hits + self._cache_misses
            cache_hit_rate = (self._cache_hits / total_cache_operations * 100) if total_cache_operations > 0 else 0

            return {
                'uptime_hours': uptime_hours,
                'total_uptime_hours': total_uptime_hours,
                'concurrent_users': self.get_concurrent_users(),
                'peak_concurrent_users': self._peak_concurrent_users,
                'avg_response_time_seconds': round(self.get_average_response_time(), 2),
                'total_queries_24h': self.get_total_queries_24h(),
                'total_lifetime_queries': self._total_lifetime_queries,
                'total_response_samples': len(self._response_times),
                'total_errors': self._error_count,
                'total_lifetime_errors': self._total_lifetime_errors,
                'last_error_time': self._last_error_time.isoformat() if self._last_error_time else None,
                'cache_hit_rate': round(cache_hit_rate, 1),
                'cache_hits': self._cache_hits,
                'cache_misses': self._cache_misses,
                'query_types': dict(self._query_types),
                'system': {
                    'memory_percent': round(memory_stats['system_memory_percent'], 1),
                    'memory_available_gb': round(memory_stats['system_memory_available_gb'], 1),
                    'memory_total_gb': round(memory_stats['system_memory_total_gb'], 1),
                    'process_memory_mb': round(memory_stats['process_memory_mb'], 1),
                    'process_memory_percent': round(memory_stats['process_memory_percent'], 1),
                    'cpu_percent': round(system_stats['cpu_percent'], 1),
                    'disk_percent': round(system_stats['disk_percent'], 1),
                    'disk_free_gb': round(system_stats['disk_free_gb'], 1)
                }
            }

    def get_capacity_warning(self) -> Optional[str]:
        """Check if system is under stress and return warning message"""
        with self._lock:
            warnings = []

            # Check concurrent users
            concurrent = self.get_concurrent_users()
            if concurrent > 50:
                warnings.append(f"High concurrent users: {concurrent}")

            # Check memory usage
            memory_stats = self.get_memory_usage()
            if memory_stats['system_memory_percent'] > 85:
                warnings.append(f"High memory usage: {memory_stats['system_memory_percent']:.1f}%")

            # Check response time
            avg_response = self.get_average_response_time()
            if avg_response > 10:
                warnings.append(f"Slow response time: {avg_response:.1f}s")

            # Check error rate
            if self._error_count > 10:
                warnings.append(f"High error count: {self._error_count}")

            return "; ".join(warnings) if warnings else None

    def save_data(self) -> None:
        """Manually save performance data"""
        self._save_persistent_data()

    def reset_stats(self) -> None:
        """Reset all statistics"""
        with self._lock:
            self._start_time = datetime.now()
            self._active_requests.clear()
            self._peak_concurrent_users = 0
            self._response_times.clear()
            self._hourly_queries.clear()
            self._error_count = 0
            self._last_error_time = None
            self._cache_hits = 0
            self._cache_misses = 0
            self._query_types.clear()
            self._total_lifetime_queries = 0
            self._total_lifetime_errors = 0
            self._initial_start_time = datetime.now()

            # Save the reset state
            self._save_persistent_data()