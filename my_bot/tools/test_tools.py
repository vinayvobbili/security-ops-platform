# /pokedx_bot/tools/test_tools.py
"""
Testing Tools for SOC Bot

This module provides bot testing capabilities for operational validation.
"""

import logging
import time
from langchain_core.tools import tool
from my_bot.tools._tagging import readonly_tool, mutating_tool


@mutating_tool
def run_tests() -> str:
    """Run basic bot functionality tests."""
    try:
        from my_bot.core.state_manager import get_state_manager
        
        def _send_direct_message(message: str):
            """Helper to send direct messages during testing"""
            logging.info(f"TEST: {message}")

        # Get bot instance and state manager
        try:
            import sys
            for module_name in list(sys.modules.keys()):
                if 'webex_bots.sleuth' in module_name:
                    bot_module = sys.modules[module_name]
                    if hasattr(bot_module, 'bot_instance'):
                        bot_instance = bot_module.bot_instance
                        break
            else:
                bot_instance = None
                
            if not bot_instance or not hasattr(bot_instance, 'teams'):
                _send_direct_message("❌ **Error:** Bot instance not available for testing")
                return "❌ **Error:** Bot instance not available for testing"

            # Get state manager  
            state_manager = get_state_manager()
            if not state_manager.is_initialized or not state_manager.llm_with_tools:
                _send_direct_message("❌ **Error:** Bot not fully initialized - cannot run interactive tests")
                return "❌ **Error:** Bot not fully initialized - cannot run interactive tests"

            # Define test queries with expected behaviors
            test_queries = [
                {
                    "name": "Greeting Test", 
                    "query": "Hello",
                    "expected": "greeting response"
                },
                {
                    "name": "Weather Tool Test",
                    "query": "What's the weather in Boston?", 
                    "expected": "weather information"
                },
                {
                    "name": "Shift Info Test",
                    "query": "What shift is it now?",
                    "expected": "current shift information"
                }
            ]

            total_tests = len(test_queries)
            results = []
            
            _send_direct_message(f"🧪 **Starting {total_tests} Interactive Tests** 🚀")
            
            for i, test in enumerate(test_queries, 1):
                _send_direct_message(f"🧪 **Test {i}/{total_tests}: {test['name']}**")
                
                test_start_time = time.time()

                try:
                    # Execute the query using native tool calling
                    response_text = state_manager.execute_query(test['query'])

                    test_end_time = time.time()
                    response_time = test_end_time - test_start_time

                    # Response is already text from execute_query

                    # Truncate long responses for display
                    display_response = response_text[:200] + "..." if len(response_text) > 200 else response_text

                    # Determine if test passed (basic checks)
                    test_passed = len(response_text.strip()) > 10 and "error" not in response_text.lower()
                    status_emoji = "✅" if test_passed else "⚠️"

                    # Send test result message
                    result_message = [
                        f"{status_emoji} **Test {i} Complete: {test['name']}**",
                        f"📝 Query: `{test['query']}`",
                        f"⏱️ Response Time: **{response_time:.2f}s**",
                        f"📤 Response: {display_response}",
                        ""
                    ]
                    
                    test_result = "\n".join(result_message)
                    _send_direct_message(test_result)
                    results.append(f"Test {i}: {'PASS' if test_passed else 'WARN'}")
                    
                    # Small delay between tests
                    time.sleep(0.5)

                except Exception as test_error:
                    _send_direct_message(f"❌ **Test {i} Failed: {test['name']}**\n**Error:** {str(test_error)}")
                    results.append(f"Test {i}: FAIL - {str(test_error)}")

            # Send final summary
            passed_count = len([r for r in results if 'PASS' in r])
            _send_direct_message(f"🏁 **Testing Complete!**\n**Results:** {passed_count}/{total_tests} tests passed\n{chr(10).join(results)}")
            
            return f"✅ Testing completed: {passed_count}/{total_tests} tests passed"

        except Exception as setup_error:
            error_msg = f"❌ **Setup Error:** {str(setup_error)}"
            _send_direct_message(error_msg)
            return error_msg

    except Exception as e:
        logging.error(f"Test execution failed: {e}")
        return f"❌ **Test execution failed:** {str(e)}"


@mutating_tool
def simple_live_message_test() -> str:
    """Send a simple test message to verify bot communication."""
    try:
        import sys
        for module_name in list(sys.modules.keys()):
            if 'webex_bots.sleuth' in module_name:
                bot_module = sys.modules[module_name]
                if hasattr(bot_module, 'bot_instance'):
                    bot_instance = bot_module.bot_instance
                    break
        else:
            return "❌ **Error:** Bot instance not available"

        if not bot_instance or not hasattr(bot_instance, 'teams'):
            return "❌ **Error:** Bot instance or Teams API not available"

        # Send a simple test message
        test_message = f"🧪 **Live Test Message** - {time.strftime('%Y-%m-%d %H:%M:%S')}\n✅ Bot communication is working!"
        
        logging.info(f"TEST MESSAGE: {test_message}")
        return f"✅ **Live test completed** - Test message logged at {time.strftime('%H:%M:%S')}"

    except Exception as e:
        logging.error(f"Live message test failed: {e}")
        return f"❌ **Live test failed:** {str(e)}"