#!/bin/bash

# Simple test script for macOS
echo "Hello from the test script! This script is running on the target MacBook."

# Create a test file in the /tmp directory
echo "This is a test file created by the script." > /tmp/test_file_mac.txt

# Print the contents of the test file
echo "Contents of /tmp/test_file_mac.txt:"
cat /tmp/test_file_mac.txt