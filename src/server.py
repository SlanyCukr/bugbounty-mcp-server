#!/usr/bin/env python3
"""
Bug Bounty MCP Server.

Focused on bug bounty hunting workflows and REST API endpoints.
Clean, lightweight architecture for core functionality.
"""

import os

from flask import Flask

from logger import get_logger

# Import managers for workflows to use
# Import tools and registry
from utils.registry import register_all_endpoints

# Flask app configuration
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Register all tool endpoints
register_all_endpoints(app)

# API Configuration
API_PORT = int(os.environ.get("BUGBOUNTY_MCP_PORT", 8888))
API_HOST = os.environ.get("BUGBOUNTY_MCP_HOST", "127.0.0.1")
DEBUG_MODE = os.environ.get("DEBUG", "false").lower() == "true"

logger = get_logger(__name__)


def main():
    """Start the bug bounty MCP server."""
    # Startup message
    logger.info("=" * 60)
    logger.info("🎯 Bug Bounty MCP Server Starting")
    logger.info("=" * 60)
    logger.info(f"🔗 Host: {API_HOST}")
    logger.info(f"🚪 Port: {API_PORT}")
    logger.info(f"🐛 Debug: {DEBUG_MODE}")
    logger.info(f"📝 Log file: logs/{__name__}.log")
    logger.info("🚀 Server ready for bug bounty hunting!")

    # Start Flask server
    app.run(host=API_HOST, port=API_PORT, debug=DEBUG_MODE)


if __name__ == "__main__":
    main()
