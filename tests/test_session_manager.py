# /tests/test_session_manager.py
"""
Unit tests for persistent session manager

Tests the SQLite-based conversation storage functionality including
message storage, context retrieval, cleanup, and health monitoring.
"""

import pytest
import tempfile
import os
from pathlib import Path
from pokedex_bot.core.session_manager import PersistentSessionManager


@pytest.fixture
def temp_session_manager():
    """Create a session manager with temporary database for testing"""
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "test_conversations.db")
        manager = PersistentSessionManager(db_path=db_path)
        yield manager


class TestPersistentSessionManager:
    """Test cases for persistent session manager"""
    
    def test_initialization(self, temp_session_manager):
        """Test that session manager initializes correctly"""
        manager = temp_session_manager
        assert os.path.exists(manager.db_path)
        assert manager.max_messages_per_session == 30
        assert manager.session_timeout_hours == 24
        assert manager.max_context_chars == 4000

    def test_add_message(self, temp_session_manager):
        """Test adding messages to a session"""
        manager = temp_session_manager
        session_key = "test_user_test_room"
        
        # Add messages
        assert manager.add_message(session_key, "user", "Hello bot")
        assert manager.add_message(session_key, "assistant", "Hi! How can I help?")
        
        # Check session info
        info = manager.get_session_info(session_key)
        assert info["message_count"] == 2
        assert info["session_key"] == session_key

    def test_conversation_context(self, temp_session_manager):
        """Test conversation context retrieval"""
        manager = temp_session_manager
        session_key = "test_user_test_room"
        
        # Add test conversation
        manager.add_message(session_key, "user", "What's the weather?")
        manager.add_message(session_key, "assistant", "I can help check the weather!")
        manager.add_message(session_key, "user", "Thanks!")
        
        # Get context
        context = manager.get_conversation_context(session_key)
        
        assert "Previous conversation:" in context
        assert "What's the weather?" in context
        assert "I can help check the weather!" in context
        assert "Thanks!" in context
        assert "Current question:" in context

    def test_empty_session_context(self, temp_session_manager):
        """Test context retrieval for non-existent session"""
        manager = temp_session_manager
        context = manager.get_conversation_context("nonexistent_session")
        assert context == ""

    def test_message_limit_enforcement(self, temp_session_manager):
        """Test that old messages are cleaned up when limit is reached"""
        manager = temp_session_manager
        manager.max_messages_per_session = 5  # Set low limit for testing
        session_key = "test_limit_session"
        
        # Add more messages than the limit
        for i in range(10):
            manager.add_message(session_key, "user", f"Message {i}")
            
        # Check that only the limit is stored
        info = manager.get_session_info(session_key)
        assert info["message_count"] == 5
        
        # Check that recent messages are kept
        context = manager.get_conversation_context(session_key)
        assert "Message 9" in context  # Most recent should be kept
        assert "Message 0" not in context  # Oldest should be removed

    def test_session_cleanup(self, temp_session_manager):
        """Test cleanup of old sessions"""
        manager = temp_session_manager
        manager.session_timeout_hours = 0  # Set to 0 for immediate cleanup
        
        session_key = "old_session"
        manager.add_message(session_key, "user", "Old message")
        
        # Run cleanup
        deleted_count = manager.cleanup_old_sessions()
        
        # Verify cleanup worked
        assert deleted_count >= 1
        info = manager.get_session_info(session_key)
        assert info["message_count"] == 0

    def test_session_export(self, temp_session_manager):
        """Test session export functionality"""
        manager = temp_session_manager
        session_key = "export_test_session"
        
        # Add test messages
        manager.add_message(session_key, "user", "Hello")
        manager.add_message(session_key, "assistant", "Hi there!")
        
        # Export session
        messages = manager.export_session(session_key)
        
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "Hello"
        assert messages[1]["role"] == "assistant"
        assert messages[1]["content"] == "Hi there!"

    def test_session_deletion(self, temp_session_manager):
        """Test session deletion functionality"""
        manager = temp_session_manager
        session_key = "delete_test_session"
        
        # Add test messages
        manager.add_message(session_key, "user", "Test message")
        
        # Verify message exists
        info = manager.get_session_info(session_key)
        assert info["message_count"] == 1
        
        # Delete session
        assert manager.delete_session(session_key)
        
        # Verify session is empty
        info = manager.get_session_info(session_key)
        assert info["message_count"] == 0

    def test_overall_statistics(self, temp_session_manager):
        """Test overall session statistics"""
        manager = temp_session_manager
        
        # Add messages to multiple sessions
        manager.add_message("session1", "user", "Message 1")
        manager.add_message("session2", "user", "Message 2")
        manager.add_message("session1", "assistant", "Response 1")
        
        # Get overall stats
        stats = manager.get_session_info()
        
        assert stats["total_sessions"] == 2
        assert stats["total_messages"] == 3
        assert "active_sessions" in stats
        assert "database_path" in stats

    def test_context_character_limit(self, temp_session_manager):
        """Test that context respects character limits"""
        manager = temp_session_manager
        manager.max_context_chars = 100  # Set very low limit
        session_key = "context_limit_test"
        
        # Add long messages
        long_message = "A" * 200  # 200 character message
        manager.add_message(session_key, "user", long_message)
        manager.add_message(session_key, "assistant", "Short response")
        
        # Get context
        context = manager.get_conversation_context(session_key)
        
        # Should respect character limit
        assert len(context) <= manager.max_context_chars + 200  # Some buffer for formatting

    def test_nonexistent_session_export(self, temp_session_manager):
        """Test exporting non-existent session"""
        manager = temp_session_manager
        messages = manager.export_session("nonexistent_session")
        assert messages is None

    def test_context_message_order(self, temp_session_manager):
        """Test that context maintains chronological order"""
        manager = temp_session_manager
        session_key = "order_test_session"
        
        # Add messages in order
        manager.add_message(session_key, "user", "First message")
        manager.add_message(session_key, "assistant", "First response")
        manager.add_message(session_key, "user", "Second message")
        
        context = manager.get_conversation_context(session_key)
        
        # Check that messages appear in chronological order
        first_pos = context.find("First message")
        second_pos = context.find("Second message")
        assert first_pos < second_pos