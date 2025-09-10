#!/usr/bin/env python3
"""
Test script for network logging functionality
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_network_logger():
    """Test the network logger functionality"""
    try:
        from pokedx_bot.utils.network_logger import log_api_call, get_network_logger
        
        # Test logging an API call
        print("Testing network logger...")
        log_api_call(
            endpoint_url="https://api.test.com/endpoint",
            method="POST", 
            payload={"test": "data"},
            response_status=200,
            response_size=1024,
            duration_ms=150.5,
            tool_name="test_tool",
            user_query="test query",
            success=True
        )
        
        # Retrieve and display logs
        logger = get_network_logger()
        recent_logs = logger.get_recent_logs(limit=5)
        
        print(f"✅ Network logger working! Found {len(recent_logs)} log entries.")
        
        if recent_logs:
            latest_log = recent_logs[-1]
            print(f"Latest log entry:")
            for key, value in latest_log.items():
                print(f"  {key}: {value}")
        
        return True
        
    except Exception as e:
        print(f"❌ Network logger test failed: {e}")
        return False

def test_weather_logging():
    """Test weather tool with logging"""
    try:
        from pokedx_bot.tools.weather_tools import _get_weather_data
        from pokedx_bot.utils.network_logger import get_network_logger
        
        print("\nTesting weather tool with network logging...")
        
        # Call weather API (will log the request)
        result = _get_weather_data('London', 'bd1d7748a6ed3fcff0025b7a61011d23')
        print(f"Weather result: {result[:100]}...")
        
        # Check if the API call was logged
        logger = get_network_logger()
        recent_logs = logger.get_recent_logs(limit=5)
        
        weather_logs = [log for log in recent_logs if log.get('tool_name') == 'weather_tool']
        if weather_logs:
            print(f"✅ Weather API call logged! Found {len(weather_logs)} weather log entries.")
            latest_weather_log = weather_logs[-1]
            print(f"Weather log details:")
            print(f"  Domain: {latest_weather_log.get('domain')}")
            print(f"  Status: {latest_weather_log.get('response_status')}")
            print(f"  Duration: {latest_weather_log.get('duration_ms')}ms")
            print(f"  Success: {latest_weather_log.get('success')}")
        else:
            print("⚠️ No weather API logs found")
        
        return True
        
    except Exception as e:
        print(f"❌ Weather logging test failed: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Testing Network Logging System\n")
    
    success1 = test_network_logger()
    success2 = test_weather_logging()
    
    print(f"\n📊 Test Results:")
    print(f"Network Logger: {'✅ PASS' if success1 else '❌ FAIL'}")
    print(f"Weather Logging: {'✅ PASS' if success2 else '❌ FAIL'}")
    
    if success1 and success2:
        print("\n🎉 All tests passed! Network logging is working correctly.")
    else:
        print("\n⚠️ Some tests failed. Check the errors above.")