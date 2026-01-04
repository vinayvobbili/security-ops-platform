#!/usr/bin/env python3
"""
Test script for executive summary generation feature.

This script tests the new generate_executive_summary tool that allows
SOC analysts to quickly generate executive summaries from XSOAR tickets.
"""

import sys
from pathlib import Path

# Add project root to Python path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

# Setup logging
import logging
from src.utils.logging_utils import setup_logging

setup_logging(
    bot_name='test_exec_summary',
    log_level=logging.INFO,
    log_dir=str(PROJECT_ROOT / "logs"),
    info_modules=['__main__', 'my_bot.tools.xsoar_tools'],
    rotate_on_startup=False
)

logger = logging.getLogger(__name__)


def test_direct_tool_call():
    """Test the tool directly without LLM agent"""
    print("\n" + "=" * 80)
    print("TEST 1: Direct Tool Call")
    print("=" * 80)

    from my_bot.tools.xsoar_tools import generate_executive_summary

    # Test with a known ticket ID (use ticket from the code: 929947)
    ticket_id = "929947"

    print(f"\n🔍 Testing executive summary generation for ticket {ticket_id}...")

    try:
        result = generate_executive_summary.invoke({"ticket_id": ticket_id})
        print("\n✅ SUCCESS! Executive summary generated:")
        print("-" * 80)
        print(result)
        print("-" * 80)
        return True
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        logger.error(f"Direct tool call failed: {e}", exc_info=True)
        return False


def test_through_llm_agent():
    """Test the tool through the LLM agent (simulates real usage)"""
    print("\n" + "=" * 80)
    print("TEST 2: LLM Agent Integration")
    print("=" * 80)

    from my_bot.core.my_model import initialize_model_and_agent, ask

    print("\n🚀 Initializing LLM agent...")
    if not initialize_model_and_agent():
        print("❌ Failed to initialize LLM agent")
        return False

    print("✅ LLM agent initialized successfully")

    # Test query simulating user message in Webex
    test_query = "Write an executive summary for X#929947"

    print(f"\n💬 Simulating Webex message: '{test_query}'")
    print("⏳ Waiting for LLM response (this may take 20-30 seconds)...\n")

    try:
        result = ask(test_query, user_id="test_user", room_id="test_room")

        print("\n✅ SUCCESS! LLM response received:")
        print("-" * 80)
        print(result['content'])
        print("-" * 80)
        print(f"\n📊 Performance metrics:")
        print(f"   • Total tokens: {result['total_tokens']} ({result['input_tokens']} in, {result['output_tokens']} out)")
        print(f"   • Generation speed: {result['tokens_per_sec']:.1f} tokens/sec")
        print(f"   • Response time: {result['prompt_time'] + result['generation_time']:.1f}s")

        return True
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        logger.error(f"LLM agent test failed: {e}", exc_info=True)
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("🧪 EXECUTIVE SUMMARY FEATURE TEST SUITE")
    print("=" * 80)
    print("\nThis script tests the new executive summary generation feature")
    print("that allows SOC analysts to generate summaries from XSOAR tickets.")

    # Run tests
    test1_passed = test_direct_tool_call()

    print("\n" + "=" * 80)
    print("⏸️  Press Enter to continue to LLM agent test (or Ctrl+C to skip)...")
    print("=" * 80)

    try:
        input()
    except KeyboardInterrupt:
        print("\n\n⏭️  Skipping LLM agent test")
        test2_passed = False
    else:
        test2_passed = test_through_llm_agent()

    # Summary
    print("\n" + "=" * 80)
    print("📋 TEST SUMMARY")
    print("=" * 80)
    print(f"Test 1 (Direct Tool Call):  {'✅ PASSED' if test1_passed else '❌ FAILED'}")
    print(f"Test 2 (LLM Agent):         {'✅ PASSED' if test2_passed else '⏭️  SKIPPED' if not test2_passed and test1_passed else '❌ FAILED'}")
    print("=" * 80)

    if test1_passed:
        print("\n🎉 Executive summary feature is working!")
        print("\n📖 USAGE INSTRUCTIONS:")
        print("   SOC analysts can now send messages like:")
        print("   • 'Write an executive summary for X#929947'")
        print("   • 'Generate exec summary for ticket 123456'")
        print("   • 'Summarize incident X#555555'")
        print("\n   The bot will automatically:")
        print("   1. Extract the ticket ID")
        print("   2. Fetch ticket details and notes from XSOAR")
        print("   3. Generate a 5-6 bullet point executive summary")
        print("   4. Return the formatted summary in Webex")
        return 0
    else:
        print("\n⚠️  Some tests failed. Check the logs for details.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
