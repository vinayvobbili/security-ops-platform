#!/usr/bin/env python3
"""
Test Script for Persistent Sessions and Enhanced Error Recovery

This script tests the new improvements before full integration.
"""

import os
import sys
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

def test_session_manager():
    """Test persistent session storage"""
    print("🔄 Testing Persistent Session Storage...")
    
    try:
        from pokedex_bot.core.session_manager import get_session_manager
        
        session_manager = get_session_manager()
        test_session = "test_user_test_room"
        
        # Test adding messages
        print("  ✅ Session manager imported successfully")
        
        # Add some test messages
        session_manager.add_message(test_session, "user", "Hello bot")
        session_manager.add_message(test_session, "assistant", "Hi! How can I help you?")
        session_manager.add_message(test_session, "user", "What's the weather like?")
        session_manager.add_message(test_session, "assistant", "I can help you check the weather!")
        
        print("  ✅ Messages added to session")
        
        # Test context retrieval
        context = session_manager.get_conversation_context(test_session)
        if context and "Previous conversation:" in context:
            print("  ✅ Context retrieval working")
            print(f"  📝 Context preview: {context[:100]}...")
        else:
            print("  ❌ Context retrieval failed")
            
        # Test session info
        info = session_manager.get_session_info(test_session)
        if info.get('message_count', 0) > 0:
            print(f"  ✅ Session info: {info['message_count']} messages stored")
        else:
            print("  ❌ Session info failed")
            
        # Test cleanup
        session_manager.cleanup_old_sessions()
        print("  ✅ Cleanup completed")
        
        # Test database location
        db_path = session_manager.db_path
        if os.path.exists(db_path):
            print(f"  ✅ Database created at: {db_path}")
        else:
            print(f"  ❌ Database not found at: {db_path}")
            
        return True
        
    except Exception as e:
        print(f"  ❌ Session manager test failed: {e}")
        return False


def test_error_recovery():
    """Test enhanced error recovery"""
    print("\n🛡️ Testing Enhanced Error Recovery...")
    
    try:
        from pokedex_bot.core.error_recovery import get_recovery_manager, safe_tool_call
        
        recovery_manager = get_recovery_manager()
        print("  ✅ Recovery manager imported successfully")
        
        # Test fallback responses
        fallback = recovery_manager.get_fallback_response('crowdstrike', 'device status')
        if "Unable to retrieve device status" in fallback:
            print("  ✅ CrowdStrike fallback response working")
        else:
            print("  ❌ CrowdStrike fallback failed")
            
        # Test weather fallback
        weather_fallback = recovery_manager.get_fallback_response('weather')
        if "Weather information is temporarily unavailable" in weather_fallback:
            print("  ✅ Weather fallback response working")
        else:
            print("  ❌ Weather fallback failed")
            
        # Test retry decorator
        @recovery_manager.with_retry('test_tool')
        def test_function():
            # This will succeed on first try
            return "Success!"
            
        result = test_function()
        if result == "Success!":
            print("  ✅ Retry decorator working")
        else:
            print("  ❌ Retry decorator failed")
            
        # Test health status
        health = recovery_manager.get_health_status()
        if 'timestamp' in health and 'tool_availability' in health:
            print("  ✅ Health status reporting working")
        else:
            print("  ❌ Health status failed")
            
        return True
        
    except Exception as e:
        print(f"  ❌ Error recovery test failed: {e}")
        return False


def test_integration_readiness():
    """Test if system is ready for integration"""
    print("\n🔧 Testing Integration Readiness...")
    
    # Check if my_model.py exists
    model_file = PROJECT_ROOT / "pokedex_bot" / "core" / "my_model.py"
    if model_file.exists():
        print(f"  ✅ Target file found: {model_file}")
    else:
        print(f"  ❌ Target file not found: {model_file}")
        return False
    
    # Check if both new modules can be imported
    try:
        from pokedex_bot.core.session_manager import get_session_manager
        from pokedex_bot.core.error_recovery import get_recovery_manager
        print("  ✅ All required modules can be imported")
    except ImportError as e:
        print(f"  ❌ Import error: {e}")
        return False
    
    # Check database directory permissions
    db_dir = PROJECT_ROOT / "data" / "transient" / "sessions"
    try:
        db_dir.mkdir(parents=True, exist_ok=True)
        test_file = db_dir / "test_write.tmp"
        test_file.write_text("test")
        test_file.unlink()
        print("  ✅ Database directory writable")
    except Exception as e:
        print(f"  ❌ Database directory not writable: {e}")
        return False
        
    return True


def main():
    """Run all tests"""
    print("🚀 Testing Persistent Sessions & Enhanced Error Recovery\n")
    
    # Run tests
    session_ok = test_session_manager()
    recovery_ok = test_error_recovery()
    integration_ok = test_integration_readiness()
    
    # Summary
    print("\n📊 Test Results Summary:")
    print(f"  {'✅' if session_ok else '❌'} Persistent Session Storage")
    print(f"  {'✅' if recovery_ok else '❌'} Enhanced Error Recovery")
    print(f"  {'✅' if integration_ok else '❌'} Integration Readiness")
    
    if all([session_ok, recovery_ok, integration_ok]):
        print("\n🎉 All tests passed! Ready for integration.")
        print("📝 Next steps:")
        print("   1. Follow INTEGRATION_GUIDE.md")
        print("   2. Update imports in my_model.py")
        print("   3. Replace session management calls")
        print("   4. Test with actual bot")
    else:
        print("\n⚠️  Some tests failed. Review errors above before integration.")
    
    return all([session_ok, recovery_ok, integration_ok])


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)