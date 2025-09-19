"""Flask REST API server exposing bug bounty tools and workflows."""

import argparse
import os

from flask import Flask

from .logger import get_logger

# Import tool and workflow packages to ensure endpoints register via decorators
from .tools import *  # noqa: F401,F403
from .utils.registry import register_all_endpoints
from .workflows import *  # noqa: F401,F403

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# Register all tool endpoints
register_all_endpoints(app)

logger = get_logger(__name__)


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Bug Bounty MCP API Server")
    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind to (overrides BUGBOUNTY_MCP_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (overrides BUGBOUNTY_MCP_PORT)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode",
    )
    return parser.parse_args()


def resolve_host(default: str, override: str | None) -> str:
    """Resolve host configuration from override or environment variable."""
    return override or os.environ.get("BUGBOUNTY_MCP_HOST", default)


def resolve_port(default: int, override: int | None) -> int:
    """Resolve port configuration from override or environment variable."""
    env_port = os.environ.get("BUGBOUNTY_MCP_PORT")
    if override is not None:
        return override
    if env_port is not None:
        try:
            return int(env_port)
        except ValueError:
            logger.warning(
                "Invalid BUGBOUNTY_MCP_PORT value '%s', falling back to %s",
                env_port,
                default,
            )
    return default


def resolve_debug(default: bool, override: bool) -> bool:
    """Resolve debug mode configuration from override or environment variable."""
    if override:
        return True
    env_value = os.environ.get("DEBUG")
    if env_value is not None:
        return env_value.lower() == "true"
    return default


def run_flask_server(
    host_override: str | None = None,
    port_override: int | None = None,
    debug_override: bool = False,
) -> None:
    """Run the traditional Flask server."""
    host = resolve_host("127.0.0.1", host_override)
    port = resolve_port(8888, port_override)
    debug_mode = resolve_debug(False, debug_override)

    logger.info("🚀 Starting Flask-based Bug Bounty MCP Server")
    logger.info("=" * 60)
    logger.info(f"🔗 Host: {host}")
    logger.info(f"🚪 Port: {port}")
    logger.info(f"🐛 Debug: {debug_mode}")
    logger.info("📋 Available endpoints:")

    from .utils.registry import get_registered_endpoints

    endpoints = get_registered_endpoints()

    logger.info("🔧 Tools:")
    for tool_name, config in endpoints["tools"].items():
        logger.info(
            "   %s: %s [%s]",
            tool_name,
            config["endpoint"],
            ", ".join(config["methods"]),
        )

    logger.info("🔄 Workflows:")
    for workflow_name, config in endpoints["workflows"].items():
        logger.info(
            "   %s: %s [%s]",
            workflow_name,
            config["endpoint"],
            ", ".join(config["methods"]),
        )

    logger.info("🚀 Server ready for bug bounty hunting!")

    app.run(host=host, port=port, debug=debug_mode)


def main() -> None:
    """Start the bug bounty MCP REST API server."""
    args = parse_args()
    run_flask_server(
        host_override=args.host,
        port_override=args.port,
        debug_override=args.debug,
    )


if __name__ == "__main__":  # pragma: no cover - convenient CLI entrypoint
    main()
