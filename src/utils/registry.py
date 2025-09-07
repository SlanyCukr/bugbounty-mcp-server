"""Registry system for auto-registering REST API endpoints with common decorators."""

import functools
from collections.abc import Callable
from typing import Any

from flask import Flask, jsonify, request

import logger

logger = logger.get_logger(__name__)

# Global registry for storing tool and workflow endpoints
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}
_WORKFLOW_REGISTRY: dict[str, dict[str, Any]] = {}


def validate_required_fields(required_fields: list[str]):
    """Decorator factory to validate required JSON fields."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            data = request.get_json()
            if not data:
                return jsonify({"error": "JSON data is required"}), 400

            for field in required_fields:
                if field not in data:
                    return jsonify({"error": f"{field.title()} is required"}), 400

            return func(*args, **kwargs)

        return wrapper

    return decorator


def handle_exceptions(func: Callable) -> Callable:
    """Decorator to handle exceptions and provide consistent error responses."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {func.__name__}: {str(e)}")
            return jsonify({"error": f"Server error: {str(e)}"}), 500

    return wrapper


def format_response(success_key: str = "result"):
    """Decorator factory to format successful responses consistently."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            # If it's already a Flask response, return as-is
            if hasattr(result, "status_code"):
                return result
            # Format successful responses
            return jsonify(
                {
                    "success": True,
                    success_key: result,
                }
            )

        return wrapper

    return decorator


def tool(
    name: str | None = None,
    methods: list[str] | None = None,
    required_fields: list[str] | None = None,
):
    """
    Decorator to register tool execution endpoints.

    Args:
        name: Tool name (defaults to function name without 'execute_' prefix)
        methods: HTTP methods (defaults to ['POST'])
        required_fields: Required JSON fields (defaults to ['target'])
    """
    if methods is None:
        methods = ["POST"]
    if required_fields is None:
        required_fields = ["target"]

    def decorator(func: Callable) -> Callable:
        tool_name = name or func.__name__.replace("execute_", "")
        endpoint = f"/api/tools/{tool_name}"

        # Apply decorators in order
        decorated_func = handle_exceptions(func)
        decorated_func = validate_required_fields(required_fields)(decorated_func)
        decorated_func = format_response()(decorated_func)

        _TOOL_REGISTRY[tool_name] = {
            "function": decorated_func,
            "methods": methods,
            "endpoint": endpoint,
            "original_function": func,
        }

        logger.info(f"Registered tool: {tool_name} at {endpoint}")
        return func

    return decorator


def workflow(
    name: str | None = None,
    required_fields: list[str] | None = None,
    methods: list[str] | None = None,
):
    """
    Decorator to register workflow creation endpoints.

    Args:
        name: Workflow name (defaults to function name without 'create_' prefix and '_workflow' suffix)
        required_fields: Required JSON fields (defaults to ['domain'])
        methods: HTTP methods (defaults to ['POST'])
    """
    if methods is None:
        methods = ["POST"]
    if required_fields is None:
        required_fields = ["domain"]

    def decorator(func: Callable) -> Callable:
        workflow_name = name or func.__name__.replace("create_", "").replace(
            "_workflow", ""
        )
        endpoint = f"/api/bugbounty/{workflow_name.replace('_', '-')}"

        # Apply decorators in order
        decorated_func = handle_exceptions(func)
        decorated_func = validate_required_fields(required_fields)(decorated_func)
        decorated_func = format_response("workflow")(decorated_func)

        _WORKFLOW_REGISTRY[workflow_name] = {
            "function": decorated_func,
            "methods": methods,
            "endpoint": endpoint,
            "original_function": func,
        }

        logger.info(f"Registered workflow: {workflow_name} at {endpoint}")
        return func

    return decorator


def register_all_endpoints(app: Flask) -> None:
    """Register all collected tool and workflow endpoints with the Flask app."""
    logger.info("Registering all endpoints...")

    # Register tool endpoints
    for tool_name, config in _TOOL_REGISTRY.items():
        app.add_url_rule(
            config["endpoint"],
            endpoint=f"tool_{tool_name}",
            view_func=config["function"],
            methods=config["methods"],
        )
        logger.info(f"Registered tool endpoint: {config['endpoint']}")

    # Register workflow endpoints
    for workflow_name, config in _WORKFLOW_REGISTRY.items():
        app.add_url_rule(
            config["endpoint"],
            endpoint=f"workflow_{workflow_name}",
            view_func=config["function"],
            methods=config["methods"],
        )
        logger.info(f"Registered workflow endpoint: {config['endpoint']}")

    logger.info(
        f"Total endpoints registered: {len(_TOOL_REGISTRY) + len(_WORKFLOW_REGISTRY)}"
    )


def get_registered_endpoints() -> dict[str, Any]:
    """Get information about all registered endpoints."""
    return {
        "tools": {
            name: {"endpoint": config["endpoint"], "methods": config["methods"]}
            for name, config in _TOOL_REGISTRY.items()
        },
        "workflows": {
            name: {"endpoint": config["endpoint"], "methods": config["methods"]}
            for name, config in _WORKFLOW_REGISTRY.items()
        },
    }
