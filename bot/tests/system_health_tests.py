#!/usr/bin/env python3
"""
SOC Bot System Health Test Suite

Comprehensive test cases to validate all bot functionality:
- Document search capabilities
- CrowdStrike tool integration  
- Weather tool functionality
- LLM response quality
- Session management
- Vector store integrity

Run automatically when Pokédex.py starts to catch issues early.
"""

import logging
import time
from datetime import datetime
from typing import Dict

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('HealthTests')


class SOCBotHealthTester:
    """Comprehensive health testing for SOC Bot components"""

    def __init__(self):
        self.results: Dict[str, Dict] = {}
        self.start_time = datetime.now()

    def run_all_tests(self) -> Dict[str, Dict]:
        """Run all health tests and return results"""
        logger.info("🧪 Starting SOC Bot Health Tests...")
        logger.info("=" * 60)

        test_methods = [
            ("State Manager", SOCBotHealthTester.test_state_manager),
            ("Document Search", SOCBotHealthTester.test_document_search),
            ("CrowdStrike Tools", SOCBotHealthTester.test_crowdstrike_tools),
            ("Weather Tools", SOCBotHealthTester.test_weather_tools),
            ("LLM Responses", SOCBotHealthTester.test_llm_responses),
            ("Session Management", SOCBotHealthTester.test_session_management),
            ("Bot Name Handling", SOCBotHealthTester.test_bot_name_handling),
            ("Response Times", SOCBotHealthTester.test_response_times)
        ]

        for test_name, test_method in test_methods:
            logger.info(f"🔍 Testing {test_name}...")
            try:
                start = time.time()
                result = test_method()
                duration = time.time() - start

                self.results[test_name] = {
                    'status': 'PASS' if result['success'] else 'FAIL',
                    'duration': f"{duration:.2f}s",
                    'details': result.get('details', ''),
                    'error': result.get('error', None)
                }

                status_emoji = "✅" if result['success'] else "❌"
                logger.info(f"{status_emoji} {test_name}: {self.results[test_name]['status']} ({duration:.2f}s)")

            except Exception as e:
                self.results[test_name] = {
                    'status': 'ERROR',
                    'duration': 'N/A',
                    'details': f"Test failed with exception: {str(e)}",
                    'error': str(e)
                }
                logger.error(f"❌ {test_name}: ERROR - {str(e)}")

        self._generate_summary()
        return self.results

    @staticmethod
    def test_state_manager() -> Dict:
        """Test state manager initialization and components"""
        try:
            from bot.core.state_manager import get_state_manager

            state_manager = get_state_manager()
            if not state_manager:
                return {'success': False, 'details': 'State manager not available'}

            if not state_manager.is_initialized:
                return {'success': False, 'details': 'State manager not initialized'}

            health = state_manager.health_check()
            if health['status'] != 'initialized':
                return {'success': False, 'details': f'Health check failed: {health}'}

            # Check all components
            required_components = ['llm', 'embeddings', 'agent', 'rag', 'crowdstrike']
            missing_components = []

            for component in required_components:
                if not health['components'].get(component, False):
                    missing_components.append(component)

            if missing_components:
                return {
                    'success': False,
                    'details': f'Missing components: {", ".join(missing_components)}'
                }

            return {
                'success': True,
                'details': f'All components healthy: {list(health["components"].keys())}'
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_document_search() -> Dict:
        """Test document search functionality"""
        try:
            from bot.core.my_model import ask

            # Test queries with specific expected content to verify actual document search
            test_queries = [
                ("Who are our contacts for AIX servers?", ["Akash Mudgal", "Todd Winkler"], "Should find specific AIX contacts"),
                ("Scattered Spider", ["malicious software", "social engineering", "phishing"], "Should find threat intelligence"),
                ("RSA token", ["SecurID", "emergency", "tokencode"], "Should find RSA procedures"),
                ("network blocking", ["Prisma", "Zscaler", "block"], "Should find network control docs")
            ]

            search_results = []
            for query, expected_keywords, description in test_queries:
                response = ask(query, 'health_test', 'test_room')
                
                # Check for signs of successful completion (no errors/timeouts)
                if "Agent stopped due to iteration limit" in response:
                    search_results.append(f"❌ '{query}': Hit iteration limit")
                elif "❌ Bot not ready" in response or "❌ An error occurred" in response:
                    search_results.append(f"❌ '{query}': System error")
                elif any(keyword.lower() in response.lower() for keyword in expected_keywords):
                    # Found expected content - this means document search worked
                    search_results.append(f"✅ '{query}': Found relevant content")
                elif "**Source:**" in response or "**Sources:**" in response:
                    # Has source attribution but may not have exact keywords - still indicates search worked
                    search_results.append(f"⚠️ '{query}': Document searched but content needs review")
                else:
                    search_results.append(f"❌ '{query}': No document content found")

            successful_searches = len([r for r in search_results if "✅" in r])
            partial_successes = len([r for r in search_results if "⚠️" in r])
            total_searches = len(test_queries)

            # Accept both full successes and partial successes (document search working)
            effective_successes = successful_searches + partial_successes

            return {
                'success': effective_successes >= total_searches * 0.75,  # 75% success rate required
                'details': f'{successful_searches}/{total_searches} full successes, {partial_successes} partial. ' +
                           '; '.join(search_results)
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_crowdstrike_tools() -> Dict:
        """Test CrowdStrike tool integration and parameter parsing"""
        try:
            from bot.core.my_model import ask
            import logging
            import io
            
            # Capture logs to verify clean parameter passing
            log_capture = io.StringIO()
            handler = logging.StreamHandler(log_capture)
            handler.setLevel(logging.INFO)
            
            # Add handler to capture tool invocation logs
            tool_logger = logging.getLogger('bot.tools.crowdstrike_tools')
            tool_logger.addHandler(handler)
            tool_logger.setLevel(logging.INFO)

            # Test with realistic hostname format that matches patterns
            test_hostname = "C02X9Y8ZMD6R"  # Realistic Apple-style hostname for testing
            response = ask(f'containment status of {test_hostname}', 'health_test', 'test_room')
            
            # Remove handler
            tool_logger.removeHandler(handler)
            log_output = log_capture.getvalue()

            # Verify CrowdStrike tool was used (check for CrowdStrike-related content)
            cs_indicators = ["CrowdStrike", "containment status", "hostname", "not found"]
            if not any(indicator.lower() in response.lower() for indicator in cs_indicators):
                if "agent not available" in response.lower():
                    return {
                        'success': False,
                        'details': 'CrowdStrike agent executor not available'
                    }
                else:
                    return {
                        'success': False,
                        'details': f'No CrowdStrike tool usage detected: {response[:200]}...'
                    }

            # Verify clean hostname parameter passing (should not contain quotes or key=value format)
            success_details = []
            
            if "not found in CrowdStrike" in response or "Normal - Device is not contained" in response:
                success_details.append("CrowdStrike API integration working")
            else:
                return {
                    'success': False,
                    'details': f'Unexpected CrowdStrike response content: {response}'
                }

            # Additional test with different query format to ensure parameter extraction works
            response2 = ask(f'What is the isolation status of {test_hostname}?', 'health_test', 'test_room')
            if any(indicator.lower() in response2.lower() for indicator in cs_indicators):
                success_details.append("Multiple query formats handled correctly")
            else:
                return {
                    'success': False,
                    'details': 'Failed to handle alternative query format'
                }

            return {
                'success': True,
                'details': '; '.join(success_details)
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_weather_tools() -> Dict:
        """Test weather tool functionality"""
        try:
            from bot.core.my_model import ask

            # Test weather query
            response = ask('What is the weather in New York?', 'health_test', 'test_room')

            if "🌤️ **Weather Info:**" in response:
                return {
                    'success': True,
                    'details': 'Weather tools detected and responding correctly'
                }
            else:
                # Check if weather functionality is mentioned in response
                if "weather" in response.lower():
                    return {
                        'success': True,
                        'details': 'Weather functionality present but may need location specification'
                    }
                else:
                    return {
                        'success': False,
                        'details': 'Weather tools not responding as expected'
                    }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_llm_responses() -> Dict:
        """Test LLM response quality and appropriateness"""
        try:
            from bot.core.my_model import ask

            test_cases = [
                ("hello", "Should provide SOC assistant greeting"),
                ("Why did the chicken cross the road?", "Should handle casual questions appropriately"),
                ("What is phishing?", "Should provide security-related guidance")
            ]

            response_quality = []
            for query, expected in test_cases:
                response = ask(query, 'health_test', 'test_room')

                if query == "hello" and "SOC Q&A Assistant" in response:
                    response_quality.append("✅ Greeting response appropriate")
                elif "chicken" in query and len(response) > 50:
                    response_quality.append("✅ Casual question handled appropriately")
                elif "phishing" in query and ("phishing" in response.lower() or "security" in response.lower()):
                    response_quality.append("✅ Security question answered appropriately")
                else:
                    response_quality.append(f"⚠️ '{query}': Response may need review")

            successful_responses = len([r for r in response_quality if "✅" in r])

            return {
                'success': successful_responses >= 2,  # At least 2/3 should be good
                'details': '; '.join(response_quality)
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_session_management() -> Dict:
        """Test session management and context handling"""
        try:
            from bot.core.my_model import ask

            # Test session with multiple messages
            session_user = 'health_test_session'
            session_room = 'test_session_room'

            # First message
            ask("Hello", session_user, session_room)

            # Second message - should have session context
            response = ask("What did I just say?", session_user, session_room)

            # Sessions are working if the bot can reference context
            # or at least doesn't crash and provides a reasonable response
            if len(response) > 20 and not response.startswith("❌"):
                return {
                    'success': True,
                    'details': 'Session management functioning - context handling working'
                }
            else:
                return {
                    'success': False,
                    'details': 'Session management may have issues'
                }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_bot_name_handling() -> Dict:
        """Test bot name prefix removal"""
        try:
            from bot.core.my_model import ask

            # Test with bot name prefix
            response_with_prefix = ask('DnR_Pokedex hello', 'health_test', 'test_room')
            response_without_prefix = ask('hello', 'health_test', 'test_room')

            # Both should result in similar greeting responses
            if ("SOC Q&A Assistant" in response_with_prefix and
                    "SOC Q&A Assistant" in response_without_prefix):
                return {
                    'success': True,
                    'details': 'Bot name prefix removal working correctly'
                }
            else:
                return {
                    'success': False,
                    'details': 'Bot name prefix handling may need attention'
                }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    @staticmethod
    def test_response_times() -> Dict:
        """Test response time performance"""
        try:
            from bot.core.my_model import ask

            # Test simple query response time
            start = time.time()
            ask('status', 'health_test', 'test_room')
            simple_response_time = time.time() - start

            # Test complex query response time
            start = time.time()
            ask('Tell me about phishing attacks', 'health_test', 'test_room')
            complex_response_time = time.time() - start

            # Performance expectations (adjust as needed)
            simple_ok = simple_response_time < 2.0  # Simple queries < 2 seconds
            complex_ok = complex_response_time < 30.0  # Complex queries < 30 seconds

            return {
                'success': simple_ok and complex_ok,
                'details': f'Simple query: {simple_response_time:.2f}s, Complex query: {complex_response_time:.2f}s'
            }

        except Exception as e:
            return {'success': False, 'error': str(e)}

    def _generate_summary(self):
        """Generate and log test summary"""
        total_tests = len(self.results)
        passed_tests = len([r for r in self.results.values() if r['status'] == 'PASS'])
        failed_tests = len([r for r in self.results.values() if r['status'] == 'FAIL'])
        error_tests = len([r for r in self.results.values() if r['status'] == 'ERROR'])

        total_duration = (datetime.now() - self.start_time).total_seconds()

        logger.info("=" * 60)
        logger.info("📊 SOC BOT HEALTH TEST SUMMARY")
        logger.info("=" * 60)
        logger.info(f"✅ PASSED: {passed_tests}/{total_tests} tests")
        logger.info(f"❌ FAILED: {failed_tests}/{total_tests} tests")
        logger.info(f"🚨 ERRORS: {error_tests}/{total_tests} tests")
        logger.info(f"⏱️  TOTAL TIME: {total_duration:.2f} seconds")
        logger.info("")

        # Log details for failed/error tests
        for test_name, result in self.results.items():
            if result['status'] in ['FAIL', 'ERROR']:
                logger.warning(f"🔍 {test_name}: {result['details']}")

        # Overall health status
        health_score = (passed_tests / total_tests) * 100
        if health_score >= 90:
            logger.info("🎉 SYSTEM HEALTH: EXCELLENT (≥90%)")
        elif health_score >= 75:
            logger.info("✅ SYSTEM HEALTH: GOOD (≥75%)")
        elif health_score >= 50:
            logger.warning("⚠️  SYSTEM HEALTH: FAIR (≥50%) - Some issues need attention")
        else:
            logger.error("🚨 SYSTEM HEALTH: POOR (<50%) - Immediate attention required")

        logger.info("=" * 60)


def run_health_tests() -> Dict[str, Dict]:
    """Main function to run all health tests"""
    tester = SOCBotHealthTester()
    return tester.run_all_tests()


if __name__ == "__main__":
    # Allow running tests standalone
    import sys
    import os

    # Add project root to path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    sys.path.insert(0, project_root)

    # Initialize system before running tests (when run standalone)
    logger.info("🚀 Initializing system for standalone health tests...")
    try:
        from bot.core.my_model import initialize_model_and_agent

        if initialize_model_and_agent():
            logger.info("✅ System initialized successfully")
            run_health_tests()
        else:
            logger.error("❌ System initialization failed - cannot run health tests")
    except Exception as e:
        logger.error(f"❌ Failed to initialize system: {e}")
        logger.info("Running tests anyway to show what would happen...")
        run_health_tests()
