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
            get_test_status_tool()
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
    """Factory function to create test execution tool"""
    @tool
    def run_tests() -> str:
        """Run the full test suite for the bot. Use this when asked to 'run tests', 'execute tests', or 'test the bot'. Note: This may take 30-60 seconds to complete."""
        try:
            project_root = Path(__file__).parent.parent.parent
            start_time = datetime.now()
            
            # Change to project directory
            original_cwd = os.getcwd()
            os.chdir(project_root)
            
            # Run pytest with verbose output and time limit
            result = subprocess.run([
                'python', '-m', 'pytest', 'tests/', '-v', '--tb=short'
            ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
            
            # Restore original directory
            os.chdir(original_cwd)
            
            end_time = datetime.now()
            execution_time = (end_time - start_time).total_seconds()
            
            # Parse test results
            output_lines = result.stdout.split('\n')
            error_lines = result.stderr.split('\n') if result.stderr else []
            
            # Extract summary line (usually the last meaningful line)
            summary_line = ""
            for line in reversed(output_lines):
                if 'passed' in line or 'failed' in line or 'error' in line:
                    summary_line = line.strip()
                    break
            
            # Format response for Webex
            if result.returncode == 0:
                # All tests passed
                response = [
                    "✅ **TEST SUITE COMPLETED SUCCESSFULLY**",
                    f"⏱️ **Execution Time:** {execution_time:.1f}s",
                    f"📊 **Results:** {summary_line}",
                    "",
                    "**Key Points:**",
                    "• All tests passed",
                    "• No critical issues detected", 
                    "• Bot functionality verified",
                    ""
                ]
                
                # Add any warnings from stderr
                if error_lines and any(line.strip() for line in error_lines):
                    warnings = [line for line in error_lines if line.strip() and 'warning' in line.lower()]
                    if warnings:
                        response.extend([
                            "**⚠️ Warnings:**",
                            *[f"• {w.strip()}" for w in warnings[:3]],  # Show first 3 warnings
                            ""
                        ])
                        
            else:
                # Some tests failed
                failed_tests = []
                for line in output_lines:
                    if 'FAILED' in line and '::' in line:
                        test_name = line.split('::')[-1].split()[0]
                        failed_tests.append(test_name)
                
                response = [
                    "❌ **TEST SUITE COMPLETED WITH FAILURES**",
                    f"⏱️ **Execution Time:** {execution_time:.1f}s", 
                    f"📊 **Results:** {summary_line}",
                    ""
                ]
                
                if failed_tests:
                    response.extend([
                        "**Failed Tests:**",
                        *[f"• `{test}`" for test in failed_tests[:5]],  # Show first 5 failures
                        ""
                    ])
                
                response.extend([
                    "**Recommended Actions:**",
                    "• Review failed test details",
                    "• Check for recent code changes",
                    "• Run specific failed tests for debugging",
                    ""
                ])
            
            # Add system info
            response.extend([
                "**Test Environment:**",
                f"• Project Root: `{project_root.name}/`",
                f"• Python: `python -m pytest`",
                f"• Test Directory: `tests/`"
            ])
            
            return "\n".join(response)
            
        except subprocess.TimeoutExpired:
            return "⏰ **Test execution timed out** (>5 minutes). Tests may be hanging or system is under heavy load."
        except subprocess.SubprocessError as e:
            return f"❌ **Test execution failed:** {str(e)}"
        except Exception as e:
            return f"❌ **Error running tests:** {str(e)}"
        finally:
            # Ensure we restore the original directory
            try:
                os.chdir(original_cwd)
            except:
                pass
    
    return run_tests


def run_specific_test_tool():
    """Factory function to create specific test execution tool"""
    @tool
    def run_specific_test(test_name: str) -> str:
        """Run a specific test file or test function. Provide the test name like 'test_staffing' or 'test_bot_tools_and_features.py'. Use this for targeted testing of specific functionality."""
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
            try:
                os.chdir(original_cwd)
            except:
                pass
    
    return run_specific_test


def get_test_status_tool():
    """Factory function to create test status tool"""
    @tool
    def get_test_status() -> str:
        """Get information about available tests and test environment status. Use this to check what tests are available before running them."""
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
                    except:
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