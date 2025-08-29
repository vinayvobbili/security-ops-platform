# /tests/test_my_model_improvements.py
"""
Integration tests for my_model.py improvements

Tests the integration of persistent sessions and enhanced error recovery
into the main SOC bot functionality.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from pokedex_bot.core.my_model import ask, initialize_model_and_agent


class TestMyModelImprovements:
    """Integration tests for my_model.py with improvements"""
    
    @patch('pokedex_bot.core.my_model.get_state_manager')
    @patch('pokedex_bot.core.my_model.get_session_manager')
    @patch('pokedex_bot.core.my_model.get_recovery_manager')
    def test_ask_with_session_storage(self, mock_recovery_mgr, mock_session_mgr, mock_state_mgr):
        """Test that ask() function uses session storage correctly"""
        # Setup mocks
        mock_session_manager = Mock()
        mock_session_mgr.return_value = mock_session_manager
        
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = True
        mock_state_mgr.return_value = mock_state_manager
        
        mock_recovery_manager = Mock()
        mock_recovery_mgr.return_value = mock_recovery_manager
        
        # Mock session manager methods
        mock_session_manager.cleanup_old_sessions.return_value = None
        mock_session_manager.get_conversation_context.return_value = ""
        mock_session_manager.add_message.return_value = True
        
        # Test simple query (fast path)
        result = ask("hello", "test_user", "test_room")
        
        # Verify session management was called
        mock_session_manager.cleanup_old_sessions.assert_called_once()
        mock_session_manager.get_conversation_context.assert_called_with("test_user_test_room")
        
        # Verify messages were stored
        assert mock_session_manager.add_message.call_count == 2
        calls = mock_session_manager.add_message.call_args_list
        assert calls[0][0] == ("test_user_test_room", "user", "hello")
        assert calls[1][0][0] == "test_user_test_room"
        assert calls[1][0][1] == "assistant"

    @patch('pokedex_bot.core.my_model.get_state_manager')
    @patch('pokedex_bot.core.my_model.get_session_manager')
    @patch('pokedex_bot.core.my_model.get_recovery_manager')
    @patch('pokedex_bot.core.my_model.enhanced_agent_wrapper')
    def test_ask_with_error_recovery(self, mock_wrapper, mock_recovery_mgr, mock_session_mgr, mock_state_mgr):
        """Test that ask() function uses enhanced error recovery"""
        # Setup mocks
        mock_session_manager = Mock()
        mock_session_mgr.return_value = mock_session_manager
        mock_session_manager.cleanup_old_sessions.return_value = None
        mock_session_manager.get_conversation_context.return_value = "Previous context"
        mock_session_manager.add_message.return_value = True
        
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = True
        mock_agent_executor = Mock()
        mock_state_manager.get_agent_executor.return_value = mock_agent_executor
        mock_state_mgr.return_value = mock_state_manager
        
        mock_recovery_manager = Mock()
        mock_recovery_mgr.return_value = mock_recovery_manager
        
        # Mock enhanced agent wrapper
        mock_wrapper.return_value = "Enhanced agent response"
        
        # Test complex query that uses agent
        result = ask("Complex security question", "test_user", "test_room")
        
        # Verify enhanced agent wrapper was called
        mock_wrapper.assert_called_once()
        args = mock_wrapper.call_args[0]
        assert args[0] == mock_agent_executor  # agent_executor
        assert "Previous context" in args[1]   # enhanced query with context
        assert "Complex security question" in args[1]
        assert args[2] == mock_recovery_manager  # recovery_manager
        
        # Verify session storage
        assert mock_session_manager.add_message.call_count == 2
        assert result == "Enhanced agent response"

    @patch('pokedex_bot.core.my_model.get_state_manager')
    @patch('pokedex_bot.core.my_model.get_session_manager')
    @patch('pokedex_bot.core.my_model.get_recovery_manager')
    @patch('pokedex_bot.core.my_model.enhanced_agent_wrapper')
    def test_ask_with_agent_failure(self, mock_wrapper, mock_recovery_mgr, mock_session_mgr, mock_state_mgr):
        """Test ask() function handles agent failures gracefully"""
        # Setup mocks
        mock_session_manager = Mock()
        mock_session_mgr.return_value = mock_session_manager
        mock_session_manager.cleanup_old_sessions.return_value = None
        mock_session_manager.get_conversation_context.return_value = ""
        mock_session_manager.add_message.return_value = True
        
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = True
        mock_state_manager.get_agent_executor.return_value = Mock()
        mock_state_mgr.return_value = mock_state_manager
        
        mock_recovery_manager = Mock()
        mock_recovery_manager.get_fallback_response.return_value = "Fallback response"
        mock_recovery_mgr.return_value = mock_recovery_manager
        
        # Mock agent wrapper to raise exception
        mock_wrapper.side_effect = Exception("Agent failed")
        
        # Test complex query that triggers agent failure
        result = ask("Complex question", "test_user", "test_room")
        
        # Verify fallback was used
        mock_recovery_manager.get_fallback_response.assert_called_once_with('general', 'Complex question')
        assert result == "Fallback response"
        
        # Verify session still stored the interaction
        assert mock_session_manager.add_message.call_count == 2

    @patch('pokedex_bot.core.my_model.get_state_manager')
    @patch('pokedex_bot.core.my_model.get_session_manager')
    def test_ask_with_conversation_context(self, mock_session_mgr, mock_state_mgr):
        """Test that conversation context is properly integrated"""
        # Setup mocks
        mock_session_manager = Mock()
        mock_session_mgr.return_value = mock_session_manager
        mock_session_manager.cleanup_old_sessions.return_value = None
        mock_session_manager.get_conversation_context.return_value = "Previous conversation context"
        mock_session_manager.add_message.return_value = True
        
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = True
        mock_state_mgr.return_value = mock_state_manager
        
        # Test simple query to avoid complex agent path
        result = ask("status", "user123", "room456")
        
        # Verify context was retrieved with correct session key
        mock_session_manager.get_conversation_context.assert_called_with("user123_room456")
        
        # For simple queries, context isn't used but should still be retrieved
        assert "System online and ready" in result

    @patch('pokedex_bot.core.my_model.get_state_manager')
    def test_ask_uninitialized_state(self, mock_state_mgr):
        """Test ask() function with uninitialized state manager"""
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = False
        mock_state_mgr.return_value = mock_state_manager
        
        result = ask("Any question", "test_user", "test_room")
        
        assert "Bot not ready" in result

    @patch('pokedex_bot.core.my_model.get_state_manager')
    def test_ask_with_empty_message(self, mock_state_mgr):
        """Test ask() function with empty or whitespace message"""
        result1 = ask("", "test_user", "test_room")
        result2 = ask("   ", "test_user", "test_room")
        result3 = ask(None, "test_user", "test_room")
        
        assert "Please ask me a question!" in result1
        assert "Please ask me a question!" in result2
        assert "Please ask me a question!" in result3

    @patch('pokedex_bot.core.my_model.get_state_manager')
    @patch('pokedex_bot.core.my_model.get_session_manager')
    def test_ask_bot_name_removal(self, mock_session_mgr, mock_state_mgr):
        """Test that bot name prefixes are properly removed from queries"""
        # Setup mocks for simple query path
        mock_session_manager = Mock()
        mock_session_mgr.return_value = mock_session_manager
        mock_session_manager.cleanup_old_sessions.return_value = None
        mock_session_manager.get_conversation_context.return_value = ""
        mock_session_manager.add_message.return_value = True
        
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = True
        mock_state_mgr.return_value = mock_state_manager
        
        # Test with bot name prefix
        result = ask("DnR_Pokedex status", "test_user", "test_room")
        
        # Verify the query was processed correctly (bot name removed)
        # Check that session was stored with clean query
        calls = mock_session_manager.add_message.call_args_list
        user_message_call = calls[0]
        assert user_message_call[0][2] == "status"  # Bot name should be removed

    @patch('pokedex_bot.core.my_model.get_state_manager')
    def test_initialize_model_and_agent_success(self, mock_state_mgr):
        """Test successful initialization"""
        mock_state_manager = Mock()
        mock_state_manager.initialize_all_components.return_value = True
        mock_state_mgr.return_value = mock_state_manager
        
        result = initialize_model_and_agent()
        
        assert result is True
        mock_state_manager.initialize_all_components.assert_called_once()

    @patch('pokedex_bot.core.my_model.get_state_manager')
    def test_initialize_model_and_agent_failure(self, mock_state_mgr):
        """Test initialization failure"""
        mock_state_manager = Mock()
        mock_state_manager.initialize_all_components.return_value = False
        mock_state_mgr.return_value = mock_state_manager
        
        result = initialize_model_and_agent()
        
        assert result is False

    def test_session_key_format(self):
        """Test that session keys are formatted correctly"""
        # This is implicitly tested in other tests, but let's be explicit
        with patch('pokedex_bot.core.my_model.get_state_manager') as mock_state_mgr, \
             patch('pokedex_bot.core.my_model.get_session_manager') as mock_session_mgr:
            
            mock_session_manager = Mock()
            mock_session_mgr.return_value = mock_session_manager
            mock_session_manager.cleanup_old_sessions.return_value = None
            mock_session_manager.get_conversation_context.return_value = ""
            mock_session_manager.add_message.return_value = True
            
            mock_state_manager = Mock()
            mock_state_manager.is_initialized = True
            mock_state_mgr.return_value = mock_state_manager
            
            # Test with various user_id and room_id combinations
            ask("hello", "user123", "room456")
            ask("hello", "user@email.com", "room_with_underscores")
            
            # Verify session keys are formatted as user_id_room_id
            calls = mock_session_manager.get_conversation_context.call_args_list
            assert calls[0][0][0] == "user123_room456"
            assert calls[1][0][0] == "user@email.com_room_with_underscores"

    @patch('pokedex_bot.core.my_model.get_state_manager')
    @patch('pokedex_bot.core.my_model.get_session_manager')
    def test_ask_performance_logging(self, mock_session_mgr, mock_state_mgr):
        """Test that performance logging works correctly"""
        # Setup mocks for simple query
        mock_session_manager = Mock()
        mock_session_mgr.return_value = mock_session_manager
        mock_session_manager.cleanup_old_sessions.return_value = None
        mock_session_manager.get_conversation_context.return_value = ""
        mock_session_manager.add_message.return_value = True
        
        mock_state_manager = Mock()
        mock_state_manager.is_initialized = True
        mock_state_mgr.return_value = mock_state_manager
        
        # Test that function executes within reasonable time
        import time
        start_time = time.time()
        result = ask("status", "test_user", "test_room")
        elapsed = time.time() - start_time
        
        # Should be very fast for simple queries
        assert elapsed < 1.0
        assert "System online and ready" in result

    def test_greeting_responses(self):
        """Test that greeting responses work correctly"""
        with patch('pokedex_bot.core.my_model.get_state_manager') as mock_state_mgr, \
             patch('pokedex_bot.core.my_model.get_session_manager') as mock_session_mgr:
            
            mock_session_manager = Mock()
            mock_session_mgr.return_value = mock_session_manager
            mock_session_manager.cleanup_old_sessions.return_value = None
            mock_session_manager.get_conversation_context.return_value = ""
            mock_session_manager.add_message.return_value = True
            
            mock_state_manager = Mock()
            mock_state_manager.is_initialized = True
            mock_state_mgr.return_value = mock_state_manager
            
            # Test various greeting formats
            greetings = ["hello", "hi", "Hello", "HI", "  hello  "]
            
            for greeting in greetings:
                result = ask(greeting, "test_user", "test_room")
                assert "Hello! I'm your SOC Q&A Assistant" in result
                assert "security operations" in result.lower()
                assert "ask me any security-related question" in result.lower()