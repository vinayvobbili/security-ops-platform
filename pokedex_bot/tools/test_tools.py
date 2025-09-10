# /pokedex_bot/tools/test_tools.py
"""
Test Execution Tools

This module provides test execution tools for the security operations bot.
Allows running pytest tests through Webex commands with safety controls.
"""

import logging
import subprocess
import os
import time
from datetime import datetime
from pathlib import Path
from langchain_core.tools import tool
# Removed module-level imports to avoid circular imports
# bot_instance and get_config will be imported inside functions when needed


class TestToolsManager:
    """Manager for test execution tools"""

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.project_root = Path(__file__).parent.parent.parent

    def get_tools(self) -> list:
        """Get list of available test tools"""
        return [
            run_tests_tool(),
            run_specific_test_tool(),
            get_test_status_tool(),
            simple_live_message_test_tool()
        ]

    def is_available(self) -> bool:
        """Check if test tools are available"""
        try:
            # Check if pytest is available and tests directory exists
            result = subprocess.run(['python', '-m', 'pytest', '--version'],
                                    capture_output=True, text=True, timeout=5)
            tests_dir = self.project_root / 'tests'
            return result.returncode == 0 and tests_dir.exists()
        except (subprocess.SubprocessError, FileNotFoundError):
            return False


def run_tests_tool():
    """Factory function to create interactive test execution tool"""

    @tool  
    def run_tests() -> str:
        """Run interactive bot functionality tests."""
        import threading
        
        def run_test_suite():
            """Run the test suite in a separate thread with live updates"""
            try:
                # Import here to avoid circular imports
                from pokedex_bot.core.state_manager import get_state_manager
                from webex_bots.pokedex import bot_instance
                from my_config import get_config

                # Check bot availability
                if not bot_instance or not hasattr(bot_instance, 'teams'):
                    _send_direct_message("❌ **Error:** Bot instance not available for testing")
                    return

                # Get state manager  
                state_manager = get_state_manager()
                if not state_manager.is_initialized or not state_manager.agent_executor:
                    _send_direct_message("❌ **Error:** Bot not fully initialized - cannot run interactive tests")
                    return

                # Define test queries with expected behaviors
                test_queries = [
                    {
                        "name": "Greeting Test", 
                        "query": "Hello",
                        "expected": "Should respond with SOC assistant greeting",
                        "timeout": 10
                    },
                    {
                        "name": "Status Check",
                        "query": "status", 
                        "expected": "Should respond with system online status",
                        "timeout": 5
                    },
                    {
                        "name": "RAG Document Search",
                        "query": "Who are our AIX server contacts?",
                        "expected": "Should search documents and provide contact information", 
                        "timeout": 30
                    },
                    {
                        "name": "Staffing Query",
                        "query": "Current staffing",
                        "expected": "Should provide current shift staffing information",
                        "timeout": 15
                    },
                    {
                        "name": "Weather Tool Test", 
                        "query": "What's the weather in London?",
                        "expected": "Should provide current weather information",
                        "timeout": 20
                    },
                    {
                        "name": "General Security Question",
                        "query": "How do I handle a malware incident?", 
                        "expected": "Should search documents or provide security guidance",
                        "timeout": 25
                    }
                ]

                # Send initial start message
                _send_direct_message("🚀 **INTERACTIVE BOT TESTS STARTING**\n\nRunning live functionality tests with real-time updates...")
                time.sleep(2)  # Brief pause for readability

                # Initialize results tracking
                test_results = []
                total_tests = len(test_queries)

                # Execute each test
                for i, test in enumerate(test_queries, 1):
                    test_start_time = time.time()

                    # Send test start message
                    _send_direct_message(f"🧪 **Test {i}/{total_tests}: {test['name']}**\n📝 Query: `{test['query']}`\n⏱️ Starting...")

                    try:
                        # Execute the query using a NEW agent instance to avoid blocking
                        response = state_manager.agent_executor.invoke({
                            "input": test['query']
                        })

                        test_end_time = time.time()
                        response_time = test_end_time - test_start_time

                        # Get response text
                        response_text = response.get('output', 'No response') if isinstance(response, dict) else str(response)

                        # Truncate long responses for display
                        display_response = response_text[:200] + "..." if len(response_text) > 200 else response_text

                        # Determine if test passed (basic checks)
                        test_passed = len(response_text.strip()) > 10 and "error" not in response_text.lower()
                        status_emoji = "✅" if test_passed else "⚠️"

                        # Send test result message
                        result_message = [
                            f"{status_emoji} **Test {i} Complete: {test['name']}**",
                            f"⏱️ **Response Time:** {response_time:.2f}s", 
                            f"📊 **Status:** {'PASS' if test_passed else 'NEEDS REVIEW'}",
                            "",
                            f"**Response Preview:**",
                            f"```{display_response}```"
                        ]
                        _send_direct_message("\n".join(result_message))

                        # Store results
                        test_results.append({
                            'name': test['name'],
                            'query': test['query'],
                            'response_time': response_time,
                            'passed': test_passed,
                            'response_length': len(response_text)
                        })

                    except Exception as test_error:
                        test_end_time = time.time()
                        response_time = test_end_time - test_start_time

                        # Send error message
                        error_message = [
                            f"❌ **Test {i} FAILED: {test['name']}**",
                            f"⏱️ **Time:** {response_time:.2f}s",
                            f"🚨 **Error:** {str(test_error)[:100]}..."
                        ]
                        _send_direct_message("\n".join(error_message))

                        # Store error results
                        test_results.append({
                            'name': test['name'],
                            'query': test['query'], 
                            'response_time': response_time,
                            'passed': False,
                            'error': str(test_error)
                        })

                    # Brief pause between tests for readability
                    time.sleep(3)

                # Send final summary
                passed_tests = sum(1 for result in test_results if result['passed'])
                avg_response_time = sum(result['response_time'] for result in test_results) / len(test_results)

                summary_message = [
                    "📊 **INTERACTIVE TEST SUITE COMPLETE**",
                    "",
                    f"**📈 Summary:**",
                    f"• Tests Passed: **{passed_tests}/{total_tests}** ({(passed_tests / total_tests) * 100:.1f}%)",
                    f"• Average Response Time: **{avg_response_time:.2f}s**", 
                    f"• Total Execution Time: **{sum(result['response_time'] for result in test_results):.1f}s**",
                    "",
                    "**🎯 Test Results:**"
                ]

                for result in test_results:
                    status_emoji = "✅" if result['passed'] else "❌"
                    summary_message.append(f"{status_emoji} {result['name']}: {result['response_time']:.2f}s")

                if passed_tests == total_tests:
                    summary_message.extend([
                        "",
                        "🎉 **All tests passed!** Bot is functioning correctly.",
                        "✅ Ready for production use."
                    ])
                else:
                    failed_tests = [r['name'] for r in test_results if not r['passed']]
                    summary_message.extend([
                        "",
                        f"⚠️ **{len(failed_tests)} tests need attention:**",
                        *[f"• {name}" for name in failed_tests],
                        "",
                        "🔧 **Recommended:** Review failed tests and check system configuration."
                    ])

                _send_direct_message("\n".join(summary_message))

            except Exception as suite_error:
                error_msg = f"❌ **Interactive test suite failed:** {str(suite_error)}"
                _send_direct_message(error_msg)

        # Start the test suite in a separate thread so the agent can return immediately
        test_thread = threading.Thread(target=run_test_suite, daemon=True)
        test_thread.start()
        
        # Return immediately to the agent
        return "✅ **Test suite started!** Check Webex for live test progress and results. Tests are running in the background."

    return run_tests


def _send_direct_message(message: str):
    """Send message directly via Webex API without going through the agent"""
    try:
        from webex_bots.pokedex import bot_instance
        from my_config import get_config
        
        if not bot_instance or not hasattr(bot_instance, 'teams'):
            logging.getLogger(__name__).warning(f"Bot instance not available. Message: {message}")
            return
            
        config = get_config()
        
        # Send directly via bot instance
        if hasattr(config, 'webex_room_id_vinay_test_space'):
            bot_instance.teams.messages.create(
                roomId=config.webex_room_id_vinay_test_space,
                markdown=message
            )
            logging.getLogger(__name__).info(f"Direct message sent to room: {message[:50]}...")
        else:
            bot_instance.teams.messages.create(
                toPersonEmail=config.my_email_address,
                markdown=message
            )
            logging.getLogger(__name__).info(f"Direct message sent to email: {message[:50]}...")
            
    except Exception as ex:
        logging.getLogger(__name__).error(f"Failed to send direct message: {ex}")
        logging.getLogger(__name__).info(f"Failed message content: {message}")


def _send_test_message(message: str):
    """Helper function to send test progress messages to Webex"""
    try:
        # Import here to avoid circular imports
        import sys
        from pathlib import Path

        # Add webex_bots directory to path
        webex_bots_path = Path(__file__).parent.parent.parent / 'webex_bots'
        if str(webex_bots_path) not in sys.path:
            sys.path.append(str(webex_bots_path))

        # Try to get the current bot instance from Pokédex module
        try:
            from webex_bots.pokedex import bot_instance
            from my_config import get_config
            
            config = get_config()

            if bot_instance and hasattr(bot_instance, 'teams'):
                # Try to send to test room first, then fallback to user email
                if hasattr(config, 'webex_room_id_vinay_test_space'):
                    bot_instance.teams.messages.create(
                        roomId=config.webex_room_id_vinay_test_space,
                        markdown=message
                    )
                    logging.getLogger(__name__).info(f"Test message sent to room: {message[:50]}...")
                else:
                    bot_instance.teams.messages.create(
                        toPersonEmail=config.my_email_address,
                        markdown=message
                    )
                    logging.getLogger(__name__).info(f"Test message sent to email: {message[:50]}...")
            else:
                logging.getLogger(__name__).warning(f"Bot instance not available or missing teams attr. bot_instance={bot_instance}")
                logging.getLogger(__name__).info(f"Test Progress: {message}")

        except ImportError as import_err:
            logging.getLogger(__name__).warning(f"Could not import bot instance: {import_err}")
            logging.getLogger(__name__).info(f"Test Progress: {message}")
        except AttributeError as attr_err:
            logging.getLogger(__name__).warning(f"Bot instance attribute error: {attr_err}")
            logging.getLogger(__name__).info(f"Test Progress: {message}")

    except Exception as e:
        # If message sending fails, just log it
        logging.getLogger(__name__).warning(f"Could not send test message: {e}")
        logging.getLogger(__name__).info(f"Test Message: {message}")


def run_specific_test_tool():
    """Factory function to create specific test execution tool"""

    @tool
    def run_specific_test(test_name: str) -> str:
        """Run a specific test file or test function by name."""
        try:
            project_root = Path(__file__).parent.parent.parent
            start_time = datetime.now()

            # Sanitize test name
            test_name = test_name.strip()
            if not test_name:
                return "❌ **Error:** Please provide a test name (e.g., 'test_staffing' or 'test_bot_tools_and_features.py')"

            # Build test path
            if test_name.endswith('.py'):
                test_path = f"tests/{test_name}"
            else:
                # Try to find matching test files
                test_path = f"tests/*{test_name}*.py"

            # Change to project directory
            original_cwd = os.getcwd()
            os.chdir(project_root)

            # Run specific test
            result = subprocess.run([
                'python', '-m', 'pytest', test_path, '-v', '--tb=short'
            ], capture_output=True, text=True, timeout=120)  # 2 minute timeout for specific tests

            # Restore original directory
            os.chdir(original_cwd)

            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()

            # Parse results
            output_lines = result.stdout.split('\n')

            # Extract summary
            summary_line = ""
            for line in reversed(output_lines):
                if 'passed' in line or 'failed' in line or 'error' in line:
                    summary_line = line.strip()
                    break

            if result.returncode == 0:
                response = [
                    f"✅ **SPECIFIC TEST COMPLETED: `{test_name}`**",
                    f"⏱️ **Execution Time:** {execution_time:.1f}s",
                    f"📊 **Results:** {summary_line}",
                    "",
                    "**Status:** All specified tests passed successfully"
                ]
            else:
                response = [
                    f"❌ **SPECIFIC TEST FAILED: `{test_name}`**",
                    f"⏱️ **Execution Time:** {execution_time:.1f}s",
                    f"📊 **Results:** {summary_line}",
                    "",
                    "**Status:** Test execution completed with failures"
                ]

            return "\n".join(response)

        except subprocess.TimeoutExpired:
            return f"⏰ **Test '{test_name}' timed out** (>2 minutes)"
        except Exception as e:
            return f"❌ **Error running specific test '{test_name}':** {str(e)}"
        finally:
            os.chdir(original_cwd)

    return run_specific_test


def get_test_status_tool():
    """Factory function to create test status tool"""

    @tool
    def get_test_status() -> str:
        """Get information about available tests and test environment status. Use when asked about test availability or test environment."""
        try:
            project_root = Path(__file__).parent.parent.parent
            tests_dir = project_root / 'tests'

            if not tests_dir.exists():
                return "❌ **Test directory not found** - Tests may not be properly configured"

            # Count test files
            test_files = list(tests_dir.glob('test_*.py'))

            response = [
                "📋 **TEST ENVIRONMENT STATUS**",
                f"🕐 **Checked:** {datetime.now().strftime('%H:%M:%S')}",
                "",
                f"**📁 Test Directory:** `{tests_dir.relative_to(project_root)}/`",
                f"**📄 Test Files:** {len(test_files)} files found",
                ""
            ]

            if test_files:
                response.append("**Available Test Files:**")
                for test_file in sorted(test_files):
                    # Try to count tests in each file
                    try:
                        content = test_file.read_text()
                        test_count = content.count('def test_')
                        response.append(f"• `{test_file.name}` ({test_count} tests)")
                    except Exception as e:
                        response.append(f"• `{test_file.name}`")

                response.extend([
                    "",
                    "**Usage Examples:**",
                    "• 'run tests' - Execute full test suite",
                    "• 'run specific test staffing' - Run staffing-related tests",
                    "• 'run specific test test_bot_tools_and_features.py' - Run specific file"
                ])
            else:
                response.append("⚠️ **No test files found** - Test suite may not be configured")

            # Check pytest availability
            try:
                result = subprocess.run(['python', '-m', 'pytest', '--version'],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    pytest_version = result.stdout.strip().split('\n')[0]
                    response.extend([
                        "",
                        f"**✅ Test Runner:** {pytest_version}"
                    ])
                else:
                    response.extend([
                        "",
                        "**❌ Test Runner:** pytest not available"
                    ])
            except:
                response.extend([
                    "",
                    "**❌ Test Runner:** pytest check failed"
                ])

            return "\n".join(response)

        except Exception as e:
            return f"❌ **Error checking test status:** {str(e)}"

    return get_test_status


def simple_live_message_test_tool():
    """Factory function to create simple live message test tool"""

    @tool
    def test_live_messaging() -> str:
        """Test tool that sends live messages during execution. Use to test if live messaging works."""
        try:
            from webex_bots.pokedex import bot_instance
            from my_config import get_config
            
            if not bot_instance or not hasattr(bot_instance, 'teams'):
                return "❌ Bot instance not available for live messaging test"
                
            config = get_config()
            
            messages = [
                "🚀 **LIVE TEST 1** - Starting live message test...",
                "⏳ **LIVE TEST 2** - Testing intermediate message...", 
                "🧪 **LIVE TEST 3** - Testing another message...",
                "✅ **LIVE TEST 4** - Final live test message"
            ]
            
            for i, message in enumerate(messages, 1):
                logging.getLogger(__name__).info(f"Sending live message {i}: {message[:30]}...")
                
                if hasattr(config, 'webex_room_id_vinay_test_space'):
                    bot_instance.teams.messages.create(
                        roomId=config.webex_room_id_vinay_test_space,
                        markdown=message
                    )
                else:
                    bot_instance.teams.messages.create(
                        toPersonEmail=config.my_email_address,
                        markdown=message
                    )
                
                logging.getLogger(__name__).info(f"Message {i} sent, waiting 3 seconds...")
                time.sleep(3)  # Wait between messages
            
            return "✅ Live messaging test completed - check Webex for 4 messages"
            
        except Exception as e:
            return f"❌ Live messaging test failed: {str(e)}"

    return test_live_messaging
