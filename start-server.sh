#!/bin/bash

# Bug Bounty MCP Server Launcher Script
# Uses uv for fast dependency management and execution

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
SERVER_TYPE="rest"
PORT=8888
HOST="127.0.0.1"
DEBUG=false

# Help function
show_help() {
    echo "Bug Bounty MCP Server Launcher"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE     Server type: 'rest' or 'mcp' (default: rest)"
    echo "  -p, --port PORT     Server port (default: 8888)"
    echo "  -H, --host HOST     Server host (default: 127.0.0.1)"
    echo "  -d, --debug         Enable debug mode"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                          # Start REST API server on default port"
    echo "  $0 --type mcp              # Start MCP server"
    echo "  $0 --debug --port 9000     # Start REST server with debug on port 9000"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            SERVER_TYPE="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -H|--host)
            HOST="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Validate server type
if [[ "$SERVER_TYPE" != "rest" && "$SERVER_TYPE" != "mcp" ]]; then
    echo -e "${RED}Error: Server type must be 'rest' or 'mcp'${NC}"
    exit 1
fi

echo -e "${BLUE}Bug Bounty MCP Server Launcher${NC}"
echo -e "${BLUE}==============================${NC}"

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${RED}Error: uv is not installed. Please install it first:${NC}"
    echo "curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

echo -e "${YELLOW}Checking dependencies...${NC}"
uv sync

echo -e "${GREEN}Dependencies synchronized successfully!${NC}"
echo ""

# Start the appropriate server
if [[ "$SERVER_TYPE" == "rest" ]]; then
    echo -e "${BLUE}Starting REST API Server...${NC}"
    echo -e "Host: ${GREEN}$HOST${NC}"
    echo -e "Port: ${GREEN}$PORT${NC}"
    echo -e "Debug: ${GREEN}$DEBUG${NC}"
    echo ""

    # Set environment variables and start server
    export BUGBOUNTY_MCP_HOST="$HOST"
    export BUGBOUNTY_MCP_PORT="$PORT"
    export DEBUG="$DEBUG"

    uv run -m src.rest_api_server
else
    echo -e "${BLUE}Starting MCP Server...${NC}"
    echo ""
    uv run -m src.mcp_server
fi
