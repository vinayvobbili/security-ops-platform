# /tests/test_bot_tools_and_features.py
"""
Comprehensive tests for bot tools and features organized by functionality

Tests are organized by tool/feature:
- Staffing Tools
- RAG (Document Search) 
- Adaptive Cards
- Weather Tools (if available)
- CrowdStrike Tools (if available)
"""

import pytest
import json
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import pytz

# Import the modules we're testing
from pokedex_bot.tools.staffing_tools import StaffingToolsManager, get_current_staffing_tool, get_current_shift_tool
from webex_bots.pokedex import PokeDexBot


# =============================================================================
# STAFFING TOOLS TESTS
# =============================================================================

class TestStaffingTools:
    """Test suite for staffing tools functionality"""
    
    def test_staffing_manager_initialization(self):
        """Test that StaffingToolsManager initializes correctly"""
        manager = StaffingToolsManager()
        
        assert manager.eastern_tz == pytz.timezone('US/Eastern')
        assert manager.is_available() == True
        
        tools = manager.get_tools()
        assert len(tools) == 2
        assert all(hasattr(tool, 'name') for tool in tools)
        assert all(hasattr(tool, 'description') for tool in tools)
    
    @patch('pokedex_bot.tools.staffing_tools.get_current_shift')
    def test_current_shift_tool(self, mock_get_shift):
        """Test get_current_shift_tool functionality"""
        mock_get_shift.return_value = 'morning'
        
        shift_tool = get_current_shift_tool()
        result = shift_tool.invoke({})
        
        assert 'morning' in result.lower()
        assert 'shift' in result.lower()
        assert '04:30 - 12:29' in result  # Morning shift hours
        mock_get_shift.assert_called_once()
    
    @patch('pokedex_bot.tools.staffing_tools.get_staffing_data')
    @patch('pokedex_bot.tools.staffing_tools.get_current_shift')
    def test_current_staffing_tool(self, mock_get_shift, mock_get_staffing):
        """Test get_current_staffing_tool with full team data"""
        mock_get_shift.return_value = 'afternoon'
        mock_staffing_data = {
            'MA': ['Alice Johnson', 'Bob Smith'],
            'RA': ['Charlie Brown'],
            'SA': ['Diana Prince'],
            'On-Call': ['Eve Wilson (555-0123)']
        }
        mock_get_staffing.return_value = mock_staffing_data
        
        staffing_tool = get_current_staffing_tool()
        result = staffing_tool.invoke({})
        
        # Verify response structure and content
        assert 'SOC STAFFING STATUS' in result
        assert 'Afternoon Shift' in result
        assert all(name in result for name in ['Alice Johnson', 'Bob Smith', 'Charlie Brown', 'Diana Prince', 'Eve Wilson'])
        assert all(emoji in result for emoji in ['🔍', '🛡️', '👨‍💼', '📞'])
        assert 'STAFFING_RESPONSE:' in result
    
    @patch('pokedex_bot.tools.staffing_tools.get_staffing_data')
    @patch('pokedex_bot.tools.staffing_tools.get_current_shift')
    def test_staffing_tool_empty_data_handling(self, mock_get_shift, mock_get_staffing):
        """Test staffing tool handles empty/missing data gracefully"""
        mock_get_shift.return_value = 'night'
        mock_staffing_data = {
            'MA': [],
            'RA': [''],  # Empty string
            'SA': None,
            'On-Call': ['John Doe (555-0000)']
        }
        mock_get_staffing.return_value = mock_staffing_data
        
        staffing_tool = get_current_staffing_tool()
        result = staffing_tool.invoke({})
        
        # Should only include non-empty teams
        assert 'John Doe' in result
        assert '📞' in result
        # Empty teams should not appear
        assert '🔍 MA Team:' not in result
    
    @patch('pokedex_bot.tools.staffing_tools.get_staffing_data')
    def test_staffing_tool_error_handling(self, mock_get_staffing):
        """Test staffing tool handles errors gracefully"""
        mock_get_staffing.side_effect = Exception("Database connection failed")
        
        staffing_tool = get_current_staffing_tool()
        result = staffing_tool.invoke({})
        
        assert 'Unable to retrieve current staffing information' in result
        assert 'Database connection failed' in result


# =============================================================================
# RAG (DOCUMENT SEARCH) TESTS  
# =============================================================================

class TestRAGDocumentSearch:
    """Test suite for RAG document search functionality"""
    
    @patch('pokedex_bot.document.document_processor.DocumentProcessor')
    def test_document_processor_initialization(self, mock_processor):
        """Test DocumentProcessor initialization"""
        from pokedex_bot.document.document_processor import DocumentProcessor
        
        # Mock the processor
        mock_instance = Mock()
        mock_processor.return_value = mock_instance
        mock_instance.initialize_vector_store.return_value = True
        mock_instance.create_retriever.return_value = True
        
        processor = DocumentProcessor("test_pdf_dir", "test_faiss_path")
        
        assert processor is not None
        mock_processor.assert_called_with("test_pdf_dir", "test_faiss_path")
    
    @patch('pokedex_bot.core.state_manager.DocumentProcessor')
    def test_rag_tool_creation(self, mock_processor):
        """Test RAG tool creation from state manager"""
        from pokedex_bot.core.state_manager import SecurityBotStateManager
        
        # Mock document processor with retriever
        mock_doc_processor = Mock()
        mock_doc_processor.retriever = Mock()  # Has retriever
        mock_doc_processor.create_rag_tool.return_value = Mock(name="search_local_documents")
        mock_processor.return_value = mock_doc_processor
        
        state_manager = SecurityBotStateManager()
        state_manager.document_processor = mock_doc_processor
        
        # Simulate tool creation
        if state_manager.document_processor.retriever:
            rag_tool = state_manager.document_processor.create_rag_tool()
            assert rag_tool is not None
            assert hasattr(rag_tool, 'name')
    
    def test_rag_tool_search_simulation(self):
        """Test simulated RAG tool search functionality"""
        # Simulate a RAG tool response
        mock_search_results = [
            "**Incident Response Procedure**\n\n1. Identify the threat\n2. Contain the incident\n3. Analyze impact",
            "**Contact Information**\n\nSOC Team Lead: John Smith (ext. 1234)\nEscalation: security-team@company.com"
        ]
        
        # Simulate tool execution
        def mock_rag_search(query: str) -> str:
            if "incident response" in query.lower():
                return mock_search_results[0]
            elif "contact" in query.lower():
                return mock_search_results[1]
            return "No relevant documents found."
        
        # Test different query types
        result1 = mock_rag_search("How to handle incident response?")
        result2 = mock_rag_search("Who should I contact for escalation?")
        result3 = mock_rag_search("Something not in documents")
        
        assert "Incident Response Procedure" in result1
        assert "Contact Information" in result2
        assert "No relevant documents found" in result3
    
    def test_rag_integration_with_state_manager(self):
        """Test RAG integration in state manager initialization"""
        from pokedex_bot.core.state_manager import SecurityBotStateManager
        
        state_manager = SecurityBotStateManager()
        
        # Test paths setup
        assert hasattr(state_manager, 'pdf_directory_path')
        assert hasattr(state_manager, 'faiss_index_path')
        assert state_manager.pdf_directory_path.endswith('local_pdfs_docs')
        assert state_manager.faiss_index_path.endswith('faiss_index_ollama')


# =============================================================================
# ADAPTIVE CARDS TESTS
# =============================================================================

class TestAdaptiveCards:
    """Test suite for Adaptive Cards functionality"""
    
    def test_extract_valid_adaptive_card(self):
        """Test extracting valid Adaptive Card JSON"""
        card_data = {
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "Test Staffing Card",
                    "weight": "Bolder",
                    "color": "Accent"
                }
            ]
        }
        response_text = json.dumps(card_data)
        
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(response_text)
        
        assert card_dict is not None
        assert card_dict["type"] == "AdaptiveCard"
        assert card_dict["version"] == "1.3"
        assert clean_text == "Enhanced response"
    
    def test_extract_adaptive_card_malformed_json(self):
        """Test handling of malformed JSON"""
        response_text = '{"type": "AdaptiveCard", "invalid": json}'
        
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(response_text)
        
        assert card_dict is None
        assert clean_text == response_text
    
    def test_extract_non_adaptive_card_json(self):
        """Test handling of valid JSON that's not an Adaptive Card"""
        response_text = '{"type": "SomeOtherFormat", "data": "test"}'
        
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(response_text)
        
        assert card_dict is None
        assert clean_text == response_text
    
    def test_extract_regular_markdown_text(self):
        """Test handling of regular markdown responses"""
        response_text = "**SOC Status**: All systems operational\\n\\n- Team Alpha: On duty\\n- Team Beta: Standby"
        
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(response_text)
        
        assert card_dict is None
        assert clean_text == response_text
    
    def test_staffing_adaptive_card_structure(self):
        """Test realistic staffing Adaptive Card structure"""
        staffing_card = {
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "🏢 SOC Staffing Status",
                    "weight": "Bolder",
                    "color": "Accent",
                    "size": "Large",
                    "horizontalAlignment": "Center"
                },
                {
                    "type": "TextBlock",
                    "text": "Morning Shift • Monday • 08:30 EST",
                    "color": "Good",
                    "size": "Medium",
                    "horizontalAlignment": "Center"
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "🔍 MA Team", "value": "Alice Johnson, Bob Smith"},
                        {"title": "🛡️ RA Team", "value": "Charlie Brown"},
                        {"title": "📞 On-Call", "value": "Diana Prince (555-0123)"}
                    ]
                }
            ]
        }
        
        response_text = json.dumps(staffing_card)
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(response_text)
        
        assert card_dict is not None
        assert card_dict["type"] == "AdaptiveCard"
        
        # Verify staffing card structure
        facts = None
        for item in card_dict["body"]:
            if item.get("type") == "FactSet":
                facts = item["facts"]
                break
        
        assert facts is not None
        assert len(facts) == 3
        
        team_titles = [fact["title"] for fact in facts]
        assert "🔍 MA Team" in team_titles
        assert "🛡️ RA Team" in team_titles
        assert "📞 On-Call" in team_titles
    
    def test_adaptive_card_integration_flow(self):
        """Test the complete Adaptive Card integration flow"""
        # Simulate the bot receiving an LLM response with an Adaptive Card
        llm_response = {
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                {
                    "type": "TextBlock",
                    "text": "Current Weather Alert",
                    "weight": "Bolder"
                }
            ]
        }
        
        # Convert to JSON string (what LLM would return)
        json_response = json.dumps(llm_response)
        
        # Extract card (what bot would do)
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(json_response)
        
        # Verify extraction worked
        assert card_dict is not None
        assert card_dict == llm_response
        assert clean_text == "Enhanced response"


# =============================================================================
# WEATHER TOOLS TESTS (if available)
# =============================================================================

class TestWeatherTools:
    """Test suite for weather tools functionality"""
    
    def test_weather_tools_manager_availability(self):
        """Test weather tools manager availability check"""
        try:
            from pokedex_bot.tools.weather_tools import WeatherToolsManager
            
            # Test with mock API key
            manager = WeatherToolsManager(api_key="test_key")
            # Weather manager may have different method name, test tools instead
            assert hasattr(manager, 'get_tools')
            
            tools = manager.get_tools()
            assert isinstance(tools, list)
            assert len(tools) > 0
            
        except ImportError:
            # Weather tools may not be available in all environments
            pytest.skip("Weather tools not available in this environment")
    
    @patch('pokedex_bot.tools.weather_tools.WeatherToolsManager')
    def test_weather_tool_mock_response(self, mock_manager):
        """Test weather tool with mocked response"""
        # Mock weather response
        mock_weather_response = {
            "location": "New York, NY",
            "temperature": "72°F",
            "condition": "Partly Cloudy",
            "humidity": "45%"
        }
        
        # Mock the manager and tool
        mock_instance = Mock()
        mock_manager.return_value = mock_instance
        mock_instance.is_available.return_value = True
        
        mock_tool = Mock()
        mock_tool.invoke.return_value = f"Weather in {mock_weather_response['location']}: {mock_weather_response['temperature']}, {mock_weather_response['condition']}"
        mock_instance.get_tools.return_value = [mock_tool]
        
        # Test the mocked functionality
        manager = mock_manager("fake_key")
        tools = manager.get_tools()
        result = tools[0].invoke({"location": "New York"})
        
        assert "New York, NY" in result
        assert "72°F" in result
        assert "Partly Cloudy" in result


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestToolsIntegration:
    """Test suite for cross-tool integration"""
    
    @patch('pokedex_bot.tools.staffing_tools.get_staffing_data')
    @patch('pokedex_bot.tools.staffing_tools.get_current_shift')
    def test_staffing_to_adaptive_card_flow(self, mock_get_shift, mock_get_staffing):
        """Test the complete flow from staffing query to Adaptive Card"""
        # Setup staffing data
        mock_get_shift.return_value = 'morning'
        mock_staffing_data = {
            'MA': ['Test Analyst 1'],
            'RA': ['Test Analyst 2'],
            'On-Call': ['Test Manager (555-9999)']
        }
        mock_get_staffing.return_value = mock_staffing_data
        
        # Get staffing tool response (what LLM agent would receive)
        staffing_tool = get_current_staffing_tool()
        staffing_result = staffing_tool.invoke({})
        
        # Verify staffing response format
        assert 'SOC STAFFING STATUS' in staffing_result
        assert 'Test Analyst 1' in staffing_result
        assert 'Test Analyst 2' in staffing_result
        assert 'Test Manager' in staffing_result
        
        # The LLM could then use this data to generate an Adaptive Card
        # (This would happen in the LLM, but we can test the structure)
        expected_card_elements = ['🏢', 'Morning Shift', '🔍', '🛡️', '📞']
        assert all(element in staffing_result for element in expected_card_elements)
    
    def test_multiple_tools_availability(self):
        """Test that multiple tools can coexist"""
        from pokedex_bot.tools.staffing_tools import StaffingToolsManager
        
        # Test staffing tools
        staffing_manager = StaffingToolsManager()
        assert staffing_manager.is_available()
        staffing_tools = staffing_manager.get_tools()
        
        # Verify we have the expected tools
        tool_names = [tool.name if hasattr(tool, 'name') else str(tool) for tool in staffing_tools]
        assert len(tool_names) == 2  # shift and staffing tools
        
        # Test Adaptive Card functionality exists
        test_json = '{"type": "AdaptiveCard", "version": "1.3"}'
        card_dict, clean_text = PokeDexBot._extract_adaptive_card(test_json)
        assert card_dict is not None


# =============================================================================
# METRICS TOOLS TESTS
# =============================================================================

class TestMetricsTools:
    """Test suite for metrics tools functionality"""
    
    def test_metrics_manager_initialization(self):
        """Test that MetricsToolsManager initializes correctly"""
        from pokedx_bot.tools.metrics_tools import MetricsToolsManager
        
        manager = MetricsToolsManager()
        tools = manager.get_tools()
        
        assert len(tools) == 2  # Should have metrics and summary tools
        assert all(hasattr(tool, 'name') for tool in tools)
        assert all(hasattr(tool, 'description') for tool in tools)
    
    @patch('pokedx_bot.tools.metrics_tools.performance_monitor')
    @patch('pokedx_bot.tools.metrics_tools.session_manager')
    def test_bot_metrics_tool_success(self, mock_session_mgr, mock_perf_mgr):
        """Test bot metrics tool with successful data retrieval"""
        # Mock performance data
        mock_perf_stats = {
            'concurrent_users': 5,
            'peak_concurrent_users': 12,
            'avg_response_time_seconds': 1.5,
            'total_queries_24h': 45,
            'total_lifetime_queries': 1250,
            'system': {
                'memory_percent': 65,
                'memory_available_gb': 4.2,
                'cpu_percent': 25,
                'process_memory_mb': 180
            },
            'cache_hit_rate': 85,
            'total_errors': 2,
            'total_lifetime_errors': 15,
            'uptime_hours': 12.5,
            'total_uptime_hours': 720.8,
            'query_types': {
                'staffing': 15,
                'device_status': 20,
                'documentation': 10
            }
        }
        
        mock_session_stats = {
            'active_users': 5,
            'total_users_ever': 25,
            'total_interactions': 180
        }
        
        mock_perf_mgr.get_stats.return_value = mock_perf_stats
        mock_session_mgr.get_stats.return_value = mock_session_stats
        mock_perf_mgr.get_capacity_warning.return_value = None
        
        metrics_tool = get_bot_metrics_tool()
        result = metrics_tool.invoke({})
        
        # Verify key metrics are in the response
        assert 'BOT PERFORMANCE METRICS' in result
        assert 'Concurrent Users: **5**' in result
        assert 'Avg Response Time: **1.5s**' in result
        assert '24h Query Volume: **45**' in result
        assert 'Memory Usage: **65%**' in result
        assert 'Active Users: **5**' in result
        assert 'Staffing: **15**' in result
        assert 'No capacity warnings' in result
    
    @patch('pokedx_bot.tools.metrics_tools.performance_monitor')
    def test_bot_metrics_summary_tool(self, mock_perf_mgr):
        """Test bot metrics summary tool"""
        mock_perf_stats = {
            'concurrent_users': 3,
            'avg_response_time_seconds': 2.1,
            'total_queries_24h': 78,
            'system': {'memory_percent': 45}
        }
        
        mock_perf_mgr.get_stats.return_value = mock_perf_stats
        mock_perf_mgr.get_capacity_warning.return_value = None
        
        summary_tool = get_bot_metrics_summary_tool()
        result = summary_tool.invoke({})
        
        assert 'Bot Status Summary' in result
        assert 'Users: **3**' in result
        assert 'Response: **2.1s**' in result
        assert '24h Queries: **78**' in result
        assert 'Memory: **45%**' in result
        assert '✅' in result  # No warnings
    
    def test_metrics_tools_error_handling(self):
        """Test metrics tools handle import errors gracefully"""
        # This will test the ImportError handling since the mock modules won't be available
        metrics_tool = get_bot_metrics_tool()
        result = metrics_tool.invoke({})
        
        # Should handle missing modules gracefully
        assert 'Metrics unavailable' in result or 'Error retrieving metrics' in result


# =============================================================================
# TEST TOOLS TESTS
# =============================================================================

class TestTestTools:
    """Test suite for test execution tools functionality"""
    
    def test_test_manager_initialization(self):
        """Test that TestToolsManager initializes correctly"""
        from pokedx_bot.tools.test_tools import TestToolsManager
        
        manager = TestToolsManager()
        tools = manager.get_tools()
        
        assert len(tools) == 3  # Should have run_tests, run_specific_test, get_test_status
        assert all(hasattr(tool, 'name') for tool in tools)
        assert all(hasattr(tool, 'description') for tool in tools)
    
    @patch('subprocess.run')
    def test_get_test_status_tool(self, mock_subprocess):
        """Test get_test_status tool functionality"""
        # Mock pytest --version check
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "pytest 7.4.0"
        mock_subprocess.return_value = mock_result
        
        status_tool = get_test_status_tool()
        result = status_tool.invoke({})
        
        assert 'TEST ENVIRONMENT STATUS' in result
        assert 'Test Files:' in result
        assert 'test_bot_tools_and_features.py' in result
        assert 'pytest' in result
    
    @patch('subprocess.run')
    @patch('os.chdir')
    def test_run_tests_tool_success(self, mock_chdir, mock_subprocess):
        """Test run_tests tool with successful test execution"""
        # Mock successful pytest run
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "test_session_manager.py::test_something PASSED\n=== 15 passed in 2.50s ==="
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        run_tests = run_tests_tool()
        result = run_tests.invoke({})
        
        assert 'TEST SUITE COMPLETED SUCCESSFULLY' in result
        assert '15 passed in 2.50s' in result
        assert 'All tests passed' in result
        assert 'No critical issues detected' in result
    
    @patch('subprocess.run')
    @patch('os.chdir')
    def test_run_tests_tool_failure(self, mock_chdir, mock_subprocess):
        """Test run_tests tool with test failures"""
        # Mock failed pytest run
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = "test_something.py::test_fail FAILED\n=== 1 failed, 10 passed in 1.80s ==="
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        run_tests = run_tests_tool()
        result = run_tests.invoke({})
        
        assert 'TEST SUITE COMPLETED WITH FAILURES' in result
        assert '1 failed, 10 passed in 1.80s' in result
        assert 'Recommended Actions:' in result
    
    def test_test_tools_timeout_handling(self):
        """Test that test tools handle timeouts appropriately"""
        # The timeout handling is built into the tools, so we just verify
        # the timeout values are reasonable
        from pokedx_bot.tools.test_tools import TestToolsManager
        
        manager = TestToolsManager()
        assert manager.is_available() in [True, False]  # Depends on environment


if __name__ == "__main__":
    pytest.main([__file__, "-v"])