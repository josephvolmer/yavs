#!/bin/bash
#
# Test script for YAVS Multi-Provider AI System
#

set -e

echo "========================================="
echo "YAVS Multi-Provider AI System Test"
echo "========================================="
echo

# Check if .env file exists
if [ -f .env ]; then
    echo "✓ Found .env file, loading environment variables..."
    export $(grep -v '^#' .env | xargs)
    echo
else
    echo "ℹ No .env file found. Using existing environment variables."
    echo
fi

# Check available API keys
echo "API Key Status:"
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "  ✓ ANTHROPIC_API_KEY is set (${#ANTHROPIC_API_KEY} chars)"
else
    echo "  ✗ ANTHROPIC_API_KEY not set"
fi

if [ -n "$OPENAI_API_KEY" ]; then
    echo "  ✓ OPENAI_API_KEY is set (${#OPENAI_API_KEY} chars)"
else
    echo "  ✗ OPENAI_API_KEY not set"
fi
echo

# Test provider detection
echo "Testing provider detection..."
python3 << 'PYEOF'
import os
from yavs.ai.provider import detect_provider

try:
    provider_type, model = detect_provider()
    print(f"✓ Auto-detected provider: {provider_type}")
    print(f"✓ Default model: {model}")
except Exception as e:
    print(f"✗ Detection failed: {e}")
PYEOF

echo
echo "========================================="
echo "Provider System Ready!"
echo "========================================="
echo
echo "Next steps:"
echo "1. If you have a .env file with your API keys:"
echo "   source test_multi_provider.sh"
echo
echo "2. Run a scan with AI features:"
echo "   yavs scan --all"
echo
echo "3. Generate an AI summary:"
echo "   yavs summarize yavs-results.json"
echo
echo "4. Test specific provider:"
echo "   yavs summarize yavs-results.json --provider openai"
echo

