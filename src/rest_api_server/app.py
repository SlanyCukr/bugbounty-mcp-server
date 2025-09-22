"""Flask REST API server exposing bug bounty tools and workflows."""

import argparse
import os

from flasgger import Swagger
from flask import Flask

from .logger import get_logger

# Import tool and workflow packages to ensure endpoints register via decorators
from .tools import *  # noqa: F401,F403
from .utils.registry import register_all_endpoints
from .workflows import *  # noqa: F401,F403

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def generate_swagger_paths():
    """Generate Swagger paths for all registered endpoints."""
    from .utils.registry import _TOOL_REGISTRY, _WORKFLOW_REGISTRY

    paths = {}

    # Add tool paths with tool-specific tags
    for name, config in _TOOL_REGISTRY.items():
        path = config["endpoint"]
        required_fields = config.get("required_fields", ["target"])

        # Determine request schema based on required fields
        if "target" in required_fields:
            request_schema = {"$ref": "#/definitions/ToolRequest"}
        elif "url" in required_fields:
            request_schema = {"$ref": "#/definitions/ToolRequestOptional"}
        elif "domain" in required_fields:
            request_schema = {"$ref": "#/definitions/ToolRequestOptional"}
        else:
            request_schema = {"$ref": "#/definitions/ToolRequestOptional"}

        paths[path] = {
            "post": {
                "tags": ["Tools"],
                "summary": f"Run {name} tool",
                "description": f"Execute {name} bug bounty tool.",
                "consumes": ["application/json"],
                "produces": ["application/json"],
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "description": f"Tool parameters. Required: {required_fields}",
                        "required": True,
                        "schema": request_schema,
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successful execution",
                        "schema": {"$ref": "#/definitions/SuccessResponse"},
                    },
                    "400": {
                        "description": "Validation error",
                        "schema": {"$ref": "#/definitions/ErrorResponse"},
                    },
                    "500": {
                        "description": "Server error",
                        "schema": {"$ref": "#/definitions/ErrorResponse"},
                    },
                },
            }
        }

    # Add workflow paths with workflow-specific tags
    for name, config in _WORKFLOW_REGISTRY.items():
        path = config["endpoint"]
        paths[path] = {
            "post": {
                "tags": ["Workflows"],
                "summary": f"Run {name} workflow",
                "description": f"Execute {name} bug bounty workflow.",
                "consumes": ["application/json"],
                "produces": ["application/json"],
                "parameters": [
                    {
                        "name": "body",
                        "in": "body",
                        "description": "Workflow parameters",
                        "required": True,
                        "schema": {"$ref": "#/definitions/WorkflowRequest"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Successful execution",
                        "schema": {"$ref": "#/definitions/SuccessResponse"},
                    },
                    "400": {
                        "description": "Validation error",
                        "schema": {"$ref": "#/definitions/ErrorResponse"},
                    },
                    "500": {
                        "description": "Server error",
                        "schema": {"$ref": "#/definitions/ErrorResponse"},
                    },
                },
            }
        }

    return paths


def get_swagger_config():
    """Get dynamic Swagger configuration with all registered endpoints."""
    return {
        "swagger": "2.0",
        "info": {
            "title": "Bug Bounty MCP Server API",
            "description": "REST API for bug bounty tools and workflows",
            "version": "1.0.0",
            "contact": {
                "developer": "Bug Bounty MCP Team",
                "email": "team@bugbounty.com",
            },
        },
        "host": "0.0.0.0:8888",
        "basePath": "/",
        "schemes": ["http", "https"],
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "paths": generate_swagger_paths(),
        "tags": [
            {
                "name": "Tools",
                "description": "Individual bug bounty tool execution endpoints",
            },
            {
                "name": "Workflows",
                "description": "Bug bounty workflow execution endpoints",
            },
        ],
        "definitions": {
            "ToolRequest": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target host/domain"}
                },
                "required": ["target"],
            },
            "ToolRequestOptional": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host/domain",
                    },
                    "url": {"type": "string", "description": "Target URL"},
                    "domain": {
                        "type": "string",
                        "description": "Target domain",
                    },
                },
            },
            "WorkflowRequest": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Target domain"}
                },
                "required": ["domain"],
            },
            "Finding": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "target": {"type": "string"},
                    "evidence": {"type": "object"},
                    "severity": {"type": "string"},
                    "confidence": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "raw_ref": {"type": "string"},
                },
            },
            "Stats": {
                "type": "object",
                "properties": {
                    "findings": {"type": "integer"},
                    "dupes": {"type": "integer"},
                    "payload_bytes": {"type": "integer"},
                },
            },
            "SuccessResponse": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "result": {
                        "type": "object",
                        "properties": {
                            "tool": {"type": "string"},
                            "version": {"type": "string"},
                            "params": {"type": "object"},
                            "started_at": {"type": "string", "format": "date-time"},
                            "ended_at": {"type": "string", "format": "date-time"},
                            "duration_ms": {"type": "integer"},
                            "findings": {
                                "type": "array",
                                "items": {"$ref": "#/definitions/Finding"},
                            },
                            "stats": {"$ref": "#/definitions/Stats"},
                        },
                    },
                },
            },
            "ErrorResponse": {
                "type": "object",
                "properties": {
                    "success": {"type": "boolean"},
                    "error": {"type": "string"},
                    "stage": {"type": "string"},
                    "details": {"type": "object"},
                },
            },
        },
    }


# Register all tool endpoints
register_all_endpoints(app)

swagger = Swagger(app, template=get_swagger_config())

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
    # nosec B104 - Binding to all interfaces is intentional for API server
    host = resolve_host("0.0.0.0", host_override)  # nosec B104
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
            "   %s: %s [%s] (required: %s)",
            tool_name,
            config["endpoint"],
            ", ".join(config["methods"]),
            config.get("required_fields", ["target"]),
        )

    logger.info("🔄 Workflows:")
    for workflow_name, config in endpoints["workflows"].items():
        logger.info(
            "   %s: %s [%s] (required: %s)",
            workflow_name,
            config["endpoint"],
            ", ".join(config["methods"]),
            config.get("required_fields", ["domain"]),
        )

    logger.info(f"📖 Swagger UI: http://{host}:{port}/apidocs")

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
