#!/bin/bash
#
# YAVS Easy Runner
# Quick wrapper for common YAVS operations
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Banner
show_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════╗"
    echo "║  YAVS - Vulnerability Scanner          ║"
    echo "║  Yet Another Vulnerability Scanner     ║"
    echo "╚════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Show usage
show_usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  setup       - First time setup (install dependencies)"
    echo "  scan        - Run basic scan on test fixtures"
    echo "  scan-ai     - Run scan with AI features"
    echo "  summarize   - Generate AI summary"
    echo "  demo        - Full demo (scan + AI summary)"
    echo "  check       - Check environment (API keys, etc.)"
    echo "  clean       - Clean up build artifacts"
    echo "  help        - Show all Make targets"
    echo ""
    echo "Examples:"
    echo "  $0 setup        # First time setup"
    echo "  $0 scan         # Quick scan"
    echo "  $0 demo         # Full demo with AI"
    echo ""
    echo "Advanced:"
    echo "  make <target>   # Use Makefile directly"
    echo "  make help       # See all available targets"
}

# Main
case "${1:-help}" in
    setup)
        show_banner
        echo -e "${GREEN}Setting up YAVS...${NC}"
        make quickstart
        ;;

    scan)
        show_banner
        echo -e "${GREEN}Running basic scan...${NC}"
        make scan
        make view-results
        ;;

    scan-ai)
        show_banner
        echo -e "${GREEN}Running scan with AI features...${NC}"
        make scan-ai
        make view-results
        ;;

    summarize)
        show_banner
        echo -e "${GREEN}Generating AI summary...${NC}"
        make summarize
        ;;

    demo)
        show_banner
        echo -e "${GREEN}Running full demo...${NC}"
        make demo
        ;;

    check)
        show_banner
        make check-env
        ;;

    clean)
        show_banner
        echo -e "${GREEN}Cleaning up...${NC}"
        make clean-all
        ;;

    help|--help|-h)
        show_banner
        show_usage
        echo ""
        echo -e "${BLUE}Available Make targets:${NC}"
        make help
        ;;

    *)
        show_banner
        echo -e "${RED}Unknown command: $1${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac
