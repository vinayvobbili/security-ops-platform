# /services/session_manager.py
"""
Session Management Module

This module provides thread-safe session management for multiple users,
including conversation context preservation and automatic cleanup.
"""

import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List


class SessionManager:
    """Thread-safe session management for multiple users"""

    def __init__(self, session_timeout_hours: int = 24, max_interactions_per_user: int = 10):
        self._sessions: Dict[str, List[Dict]] = {}
        self._lock = threading.RLock()  # Reentrant lock for nested calls
        self._session_timeout = timedelta(hours=session_timeout_hours)
        self._max_interactions = max_interactions_per_user
        self._last_cleanup = datetime.now()

    def add_interaction(self, user_id: str, query: str, response: str) -> None:
        """Add a query-response pair to user's session (thread-safe)"""
        with self._lock:
            current_time = datetime.now()

            # Initialize user session if it doesn't exist
            if user_id not in self._sessions:
                self._sessions[user_id] = []

            # Add new interaction
            self._sessions[user_id].append({
                'query': query,
                'response': response,
                'timestamp': current_time.isoformat(),
                'datetime': current_time  # For internal use
            })

            # Trim to max interactions
            if len(self._sessions[user_id]) > self._max_interactions:
                self._sessions[user_id] = self._sessions[user_id][-self._max_interactions:]

            # Periodic cleanup of expired sessions
            if current_time - self._last_cleanup > timedelta(hours=1):
                self._cleanup_expired_sessions()
                self._last_cleanup = current_time

    def get_context(self, user_id: str, limit: int = 3) -> str:
        """Get recent conversation context for a user (thread-safe)"""
        with self._lock:
            if user_id not in self._sessions:
                return ""

            # Filter out expired interactions
            current_time = datetime.now()
            valid_interactions = self._filter_valid_interactions(
                self._sessions[user_id], current_time
            )

            # Update the session with only valid interactions
            self._sessions[user_id] = valid_interactions

            # Get recent interactions
            recent_interactions = valid_interactions[-limit:]
            return self._format_context(recent_interactions)

    def _filter_valid_interactions(self, interactions: List[Dict], current_time: datetime) -> List[Dict]:
        """Filter out expired interactions"""
        return [
            interaction for interaction in interactions
            if current_time - interaction['datetime'] < self._session_timeout
        ]

    def _format_context(self, interactions: List[Dict]) -> str:
        """Format interactions into context string"""
        if not interactions:
            return ""
            
        context_parts = []
        for interaction in interactions:
            # Truncate long queries/responses for context
            query_snippet = self._truncate_text(interaction['query'], 100)
            response_snippet = self._truncate_text(interaction['response'], 100)
            context_parts.append(f"Previous Q: {query_snippet}")
            context_parts.append(f"Previous A: {response_snippet}")

        return "\n".join(context_parts)

    def _truncate_text(self, text: str, max_length: int) -> str:
        """Truncate text to specified length"""
        if len(text) <= max_length:
            return text
        return text[:max_length] + "..."

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions and interactions (called with lock held)"""
        current_time = datetime.now()
        users_to_remove = []

        for user_id, interactions in self._sessions.items():
            # Filter out expired interactions
            valid_interactions = self._filter_valid_interactions(interactions, current_time)

            if valid_interactions:
                self._sessions[user_id] = valid_interactions
            else:
                users_to_remove.append(user_id)

        # Remove users with no valid interactions
        for user_id in users_to_remove:
            del self._sessions[user_id]

        if users_to_remove:
            logging.info(f"Cleaned up expired sessions for {len(users_to_remove)} users")

    def get_stats(self) -> Dict[str, int]:
        """Get session statistics (thread-safe)"""
        with self._lock:
            current_time = datetime.now()
            active_users = 0
            total_interactions = 0

            for user_id, interactions in self._sessions.items():
                valid_interactions = self._filter_valid_interactions(interactions, current_time)
                if valid_interactions:
                    active_users += 1
                    total_interactions += len(valid_interactions)

            return {
                'active_users': active_users,
                'total_interactions': total_interactions,
                'total_users_ever': len(self._sessions)
            }

    def get_user_interaction_count(self, user_id: str) -> int:
        """Get the number of interactions for a specific user"""
        with self._lock:
            if user_id not in self._sessions:
                return 0
                
            current_time = datetime.now()
            valid_interactions = self._filter_valid_interactions(
                self._sessions[user_id], current_time
            )
            return len(valid_interactions)

    def clear_user_session(self, user_id: str) -> bool:
        """Clear a specific user's session"""
        with self._lock:
            if user_id in self._sessions:
                del self._sessions[user_id]
                logging.info(f"Cleared session for user: {user_id}")
                return True
            return False

    def get_active_users(self) -> List[str]:
        """Get list of currently active user IDs"""
        with self._lock:
            current_time = datetime.now()
            active_users = []
            
            for user_id, interactions in self._sessions.items():
                valid_interactions = self._filter_valid_interactions(interactions, current_time)
                if valid_interactions:
                    active_users.append(user_id)
                    
            return active_users

    def force_cleanup(self) -> Dict[str, int]:
        """Force cleanup of all expired sessions and return stats"""
        with self._lock:
            users_before = len(self._sessions)
            self._cleanup_expired_sessions()
            users_after = len(self._sessions)
            
            return {
                'users_before_cleanup': users_before,
                'users_after_cleanup': users_after,
                'users_removed': users_before - users_after
            }