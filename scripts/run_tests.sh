#!/bin/bash
# LoneWarrior Auto Test Runner
# Run this script to execute all tests on VPS

set -e

echo "=========================================="
echo "  LoneWarrior V1 - Auto Test Suite"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Ensure we're in the right directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "📁 Working directory: $PROJECT_DIR"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found!${NC}"
    exit 1
fi

# Activate venv if exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "✅ Virtual environment activated"
fi

# Install test dependencies
echo "📦 Installing test dependencies..."
pip install pytest pytest-cov -q

# Run unit tests
echo ""
echo "=========================================="
echo "  1. Running Unit Tests"
echo "=========================================="
python -m pytest tests/ -v --tb=short

# Run syntax check on all Python files
echo ""
echo "=========================================="
echo "  2. Syntax Validation"
echo "=========================================="
python -m py_compile lonewarrior/__init__.py
python -m py_compile lonewarrior/core/engine.py
python -m py_compile lonewarrior/core/event_bus.py
python -m py_compile lonewarrior/core/state_manager.py
python -m py_compile lonewarrior/storage/database.py
python -m py_compile lonewarrior/storage/models.py
echo -e "${GREEN}✅ All Python files passed syntax check${NC}"

# Run import test
echo ""
echo "=========================================="
echo "  3. Import Test"
echo "=========================================="
python -c "from lonewarrior.core.engine import SecurityEngine; print('✅ SecurityEngine imports successfully')"
python -c "from lonewarrior.storage.database import Database; print('✅ Database imports successfully')"
python -c "from lonewarrior.core.event_bus import EventBus; print('✅ EventBus imports successfully')"

echo ""
echo "=========================================="
echo -e "  ${GREEN}All Tests Passed!${NC}"
echo "=========================================="
