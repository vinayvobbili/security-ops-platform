#!/usr/bin/env python3
"""
Test script for network logging configuration switch
"""

import sys
import os
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_network_logging_enabled():
    """Test network logging when enabled"""
    try:
        # Import and temporarily modify the config
        sys.path.append('../webex_bots')
        import pokedex
        
        # Save original value
        original_value = getattr(pokedex, 'SHOULD_LOG_NETWORK_TRAFFIC', True)
        
        # Test with logging enabled
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = True
        
        from pokedex_bot.utils.network_logger import log_api_call, get_network_logger
        
        print("🧪 Testing with SHOULD_LOG_NETWORK_TRAFFIC = True")
        
        # Clear any existing logs
        logger = get_network_logger()
        initial_count = len(logger.get_recent_logs())
        
        # Log a test API call
        log_api_call(
            endpoint_url="https://api.test-enabled.com/endpoint",
            method="GET",
            tool_name="config_test",
            user_query="test enabled",
            success=True
        )
        
        # Check if log was created
        final_count = len(logger.get_recent_logs())
        
        # Also verify CSV file exists
        import os
        csv_exists = os.path.exists(logger.log_file)
        
        if final_count > initial_count and csv_exists:
            print("✅ Network logging ENABLED: API call was logged, CSV file exists")
            success_enabled = True
        elif not csv_exists:
            print("❌ Network logging ENABLED: CSV file was not created")
            success_enabled = False
        else:
            print("❌ Network logging ENABLED: API call was NOT logged")
            success_enabled = False
        
        # Restore original value
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = original_value
        
        return success_enabled
        
    except Exception as e:
        print(f"❌ Error testing enabled logging: {e}")
        return False

def test_network_logging_disabled():
    """Test network logging when disabled"""
    try:
        # Import and modify the config
        sys.path.append('../webex_bots')
        import pokedex
        
        # Save original value
        original_value = getattr(pokedex, 'SHOULD_LOG_NETWORK_TRAFFIC', True)
        
        # Test with logging disabled
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = False
        
        from pokedex_bot.utils.network_logger import log_api_call, get_network_logger
        
        print("\n🧪 Testing with SHOULD_LOG_NETWORK_TRAFFIC = False")
        
        # Get initial log count
        logger = get_network_logger()
        initial_count = len(logger.get_recent_logs())
        
        # Try to log an API call (should be ignored)
        log_api_call(
            endpoint_url="https://api.test-disabled.com/endpoint",
            method="GET",
            tool_name="config_test",
            user_query="test disabled",
            success=True
        )
        
        # Check if log was created (it shouldn't be)
        final_count = len(logger.get_recent_logs())
        
        # Also verify CSV file exists even when logging is disabled
        import os
        csv_exists = os.path.exists(logger.log_file)
        
        if final_count == initial_count and csv_exists:
            print("✅ Network logging DISABLED: API call was properly ignored, CSV file exists")
            success_disabled = True
        elif not csv_exists:
            print("❌ Network logging DISABLED: CSV file was not created")
            success_disabled = False
        else:
            print("❌ Network logging DISABLED: API call was incorrectly logged")
            success_disabled = False
        
        # Restore original value
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = original_value
        
        return success_disabled
        
    except Exception as e:
        print(f"❌ Error testing disabled logging: {e}")
        return False

def test_performance_impact():
    """Test performance impact of the configuration check"""
    import time
    
    try:
        sys.path.append('../webex_bots')
        import pokedex
        
        original_value = getattr(pokedex, 'SHOULD_LOG_NETWORK_TRAFFIC', True)
        
        from pokedex_bot.utils.network_logger import log_api_call
        
        print("\n⏱️ Testing performance impact...")
        
        # Test with logging disabled (should be fast)
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = False
        
        start_time = time.time()
        for i in range(1000):
            log_api_call(
                endpoint_url=f"https://api.perf-test-{i}.com/endpoint",
                method="GET",
                tool_name="perf_test"
            )
        disabled_duration = (time.time() - start_time) * 1000
        
        print(f"🚀 1000 calls with logging DISABLED: {disabled_duration:.2f}ms")
        
        # Test with logging enabled
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = True
        
        start_time = time.time()
        for i in range(100):  # Fewer calls since this will actually log
            log_api_call(
                endpoint_url=f"https://api.perf-test-enabled-{i}.com/endpoint",
                method="GET",
                tool_name="perf_test"
            )
        enabled_duration = (time.time() - start_time) * 1000
        
        print(f"📝 100 calls with logging ENABLED: {enabled_duration:.2f}ms")
        
        # Restore original value
        pokedex.SHOULD_LOG_NETWORK_TRAFFIC = original_value
        
        performance_ratio = enabled_duration / (disabled_duration / 10)  # Normalize for call count
        print(f"📊 Performance ratio (enabled/disabled): {performance_ratio:.2f}x")
        
        return performance_ratio < 50  # Should be much faster when disabled
        
    except Exception as e:
        print(f"❌ Error testing performance: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Network Logging Configuration Switch\n")
    
    success1 = test_network_logging_enabled()
    success2 = test_network_logging_disabled()
    success3 = test_performance_impact()
    
    print(f"\n📊 Test Results:")
    print(f"Enabled Test: {'✅ PASS' if success1 else '❌ FAIL'}")
    print(f"Disabled Test: {'✅ PASS' if success2 else '❌ FAIL'}")
    print(f"Performance Test: {'✅ PASS' if success3 else '❌ FAIL'}")
    
    if all([success1, success2, success3]):
        print("\n🎉 All tests passed! Configuration switch is working correctly.")
        print("\n💡 To disable network logging and improve performance:")
        print("   Edit webex_bots/pokedex.py and set:")
        print("   SHOULD_LOG_NETWORK_TRAFFIC = False")
    else:
        print("\n⚠️ Some tests failed. Check the configuration implementation.")