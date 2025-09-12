# /tests/test_error_recovery.py
"""
Unit tests for enhanced error recovery system

Tests retry logic, fallback responses, health monitoring,
and graceful degradation functionality.
"""

import pytest
import time
from unittest.mock import Mock, patch
from my_bot.core.error_recovery import (
    ErrorRecoveryManager, 
    safe_tool_call, 
    enhanced_agent_wrapper,
    get_recovery_manager
)


@pytest.fixture
def recovery_manager():
    """Create a fresh error recovery manager for testing"""
    return ErrorRecoveryManager()


class TestErrorRecoveryManager:
    """Test cases for error recovery manager"""
    
    def test_initialization(self, recovery_manager):
        """Test that error recovery manager initializes correctly"""
        manager = recovery_manager
        
        assert 'crowdstrike' in manager.retry_config
        assert 'weather' in manager.retry_config
        assert 'default' in manager.retry_config
        assert len(manager.fallback_responses) > 0
        assert manager.error_counts == {}

    def test_fallback_responses(self, recovery_manager):
        """Test context-aware fallback responses"""
        manager = recovery_manager
        
        # Test CrowdStrike device status fallback
        fallback = manager.get_fallback_response('crowdstrike', 'device status check')
        assert 'Unable to retrieve device status' in fallback
        assert 'CrowdStrike Falcon console' in fallback
        
        # Test CrowdStrike device details fallback
        fallback = manager.get_fallback_response('crowdstrike', 'device details info')
        assert 'Unable to retrieve device details' in fallback
        
        # Test weather fallback
        fallback = manager.get_fallback_response('weather')
        assert 'Weather information is temporarily unavailable' in fallback
        
        # Test general fallback
        fallback = manager.get_fallback_response('unknown_tool')
        assert 'temporarily unavailable' in fallback

    def test_retry_decorator_success(self, recovery_manager):
        """Test retry decorator with successful function"""
        manager = recovery_manager
        
        @manager.with_retry('test_tool')
        def successful_function():
            return "Success!"
        
        result = successful_function()
        assert result == "Success!"
        assert manager.error_counts.get('test_tool', 0) == 0

    def test_retry_decorator_with_failures(self, recovery_manager):
        """Test retry decorator with temporary failures"""
        manager = recovery_manager
        call_count = 0
        
        @manager.with_retry('test_tool')
        def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 2:  # Fail first time, succeed second
                raise Exception("Temporary failure")
            return "Success after retry!"
        
        result = flaky_function()
        assert result == "Success after retry!"
        assert call_count == 2
        assert manager.error_counts.get('test_tool', 0) == 0  # Reset on success

    def test_retry_decorator_max_retries(self, recovery_manager):
        """Test retry decorator respects max retry limits"""
        manager = recovery_manager
        manager.retry_config['test_tool'] = {'max_retries': 1, 'delay': 0.01, 'backoff': 1.0}
        
        call_count = 0
        
        @manager.with_retry('test_tool')
        def always_failing_function():
            nonlocal call_count
            call_count += 1
            raise Exception("Always fails")
        
        with pytest.raises(Exception, match="Always fails"):
            always_failing_function()
        
        assert call_count == 2  # Initial call + 1 retry
        assert manager.error_counts['test_tool'] == 2

    def test_tool_availability_tracking(self, recovery_manager):
        """Test tool availability based on error counts"""
        manager = recovery_manager
        
        # Initially available
        assert manager.is_tool_available('crowdstrike')
        
        # Simulate many errors
        for _ in range(10):
            manager._track_error('crowdstrike', 'Test error')
        
        # Should now be unavailable
        assert not manager.is_tool_available('crowdstrike')

    def test_error_count_reset(self, recovery_manager):
        """Test that error counts reset after time interval"""
        from datetime import timedelta, datetime
        manager = recovery_manager
        
        # Add some errors first
        manager._track_error('test_tool', 'Error 1')
        manager._track_error('test_tool', 'Error 2')
        assert manager.error_counts['test_tool'] == 2
        
        # Now set interval to 0 to force reset on next call
        manager.error_reset_interval = timedelta(seconds=0)
        # Force reset by calling get_health_status
        manager.get_health_status()
        assert manager.error_counts == {}

    def test_health_status_reporting(self, recovery_manager):
        """Test health status reporting"""
        manager = recovery_manager
        
        # Add some errors for testing
        manager._track_error('crowdstrike', 'Test error')
        manager._track_error('weather', 'Test error')
        
        health = manager.get_health_status()
        
        assert 'timestamp' in health
        assert 'error_counts' in health
        assert 'tool_availability' in health
        assert 'last_reset' in health
        
        assert health['error_counts']['crowdstrike'] == 1
        assert health['error_counts']['weather'] == 1
        
        assert 'crowdstrike' in health['tool_availability']
        assert 'weather' in health['tool_availability']

    def test_high_error_rate_warning(self, recovery_manager, caplog):
        """Test that high error rates generate warnings"""
        manager = recovery_manager
        
        # Simulate high error rate
        for i in range(12):
            manager._track_error('test_tool', f'Error {i}')
        
        # Check that warning was logged
        assert any('High error rate for test_tool' in record.message for record in caplog.records)


class TestSafeToolCall:
    """Test cases for safe tool call wrapper"""
    
    def test_successful_tool_call(self):
        """Test safe tool call with successful function"""
        def successful_tool():
            return "Tool success!"
        
        success, result = safe_tool_call(successful_tool, 'test_tool')
        
        assert success is True
        assert result == "Tool success!"

    def test_failing_tool_call(self):
        """Test safe tool call with failing function"""
        def failing_tool():
            raise Exception("Tool failed!")
        
        success, result = safe_tool_call(failing_tool, 'test_tool')
        
        assert success is False
        assert 'temporarily unavailable' in result

    def test_unavailable_tool_call(self):
        """Test safe tool call with unavailable tool"""
        recovery_manager = ErrorRecoveryManager()
        
        # Mark tool as unavailable
        for _ in range(10):
            recovery_manager._track_error('test_tool', 'Error')
        
        def any_tool():
            return "Should not be called"
        
        success, result = safe_tool_call(any_tool, 'test_tool', recovery_manager=recovery_manager)
        
        assert success is False
        assert 'temporarily unavailable' in result

    def test_context_aware_fallback(self):
        """Test that safe tool call provides context-aware fallbacks"""
        def failing_tool():
            raise Exception("Tool failed!")
        
        success, result = safe_tool_call(failing_tool, 'crowdstrike', context='device status')
        
        assert success is False
        assert 'Unable to retrieve device status' in result
        assert 'CrowdStrike Falcon console' in result


class TestEnhancedAgentWrapper:
    """Test cases for enhanced agent wrapper"""
    
    def test_successful_agent_execution(self):
        """Test enhanced agent wrapper with successful agent"""
        mock_agent = Mock()
        mock_agent.invoke.return_value = {'output': 'Agent response'}
        
        result = enhanced_agent_wrapper(mock_agent, 'Test query')
        
        assert result == 'Agent response'
        mock_agent.invoke.assert_called_once()

    def test_agent_execution_no_output(self):
        """Test enhanced agent wrapper with agent that returns no output"""
        mock_agent = Mock()
        mock_agent.invoke.return_value = {'other': 'data'}  # No 'output' key
        
        result = enhanced_agent_wrapper(mock_agent, 'Test query')
        
        assert 'experiencing technical difficulties' in result

    def test_agent_execution_failure(self):
        """Test enhanced agent wrapper with failing agent"""
        mock_agent = Mock()
        mock_agent.invoke.side_effect = Exception("Agent failed")
        
        result = enhanced_agent_wrapper(mock_agent, 'Test query')
        
        assert 'temporarily unavailable' in result

    def test_context_aware_agent_fallback(self):
        """Test that agent wrapper provides context-aware fallbacks"""
        mock_agent = Mock()
        mock_agent.invoke.side_effect = Exception("Agent failed")
        
        # Test different query contexts
        status_result = enhanced_agent_wrapper(mock_agent, 'What is the status of device ABC?')
        assert 'Unable to retrieve device status' in status_result
        
        weather_result = enhanced_agent_wrapper(mock_agent, 'What is the weather like today?')
        assert 'Weather information is temporarily unavailable' in weather_result
        
        doc_result = enhanced_agent_wrapper(mock_agent, 'How to handle this procedure?')
        assert 'Document search is temporarily unavailable' in doc_result

    def test_enhanced_query_formatting(self):
        """Test that agent wrapper enhances queries with recovery instructions"""
        mock_agent = Mock()
        mock_agent.invoke.return_value = {'output': 'Agent response'}
        
        enhanced_agent_wrapper(mock_agent, 'Original query')
        
        # Check that the query was enhanced
        call_args = mock_agent.invoke.call_args[0][0]
        assert 'Original query' in call_args['input']
        assert 'IMPORTANT' in call_args['input']
        assert 'tool calls fail' in call_args['input']


class TestGlobalRecoveryManager:
    """Test cases for global recovery manager singleton"""
    
    def test_singleton_behavior(self):
        """Test that get_recovery_manager returns the same instance"""
        manager1 = get_recovery_manager()
        manager2 = get_recovery_manager()
        
        assert manager1 is manager2
        assert isinstance(manager1, ErrorRecoveryManager)

    def test_manager_persistence(self):
        """Test that manager state persists across calls"""
        manager1 = get_recovery_manager()
        manager1._track_error('test_tool', 'Test error')
        
        manager2 = get_recovery_manager()
        assert manager2.error_counts['test_tool'] == 1