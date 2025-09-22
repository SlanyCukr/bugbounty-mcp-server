"""Registry system for auto-registering REST API endpoints with common decorators.

This module provides a unified API schema for bug bounty tool responses and automatic
endpoint registration system with consistent error handling and response formatting.
"""

import functools
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from flask import Flask, jsonify, request

from ..logger import get_logger

logger = get_logger(__name__)

# Type definitions for the unified API schema
FindingType = Literal["subdomain", "port", "vuln", "endpoint", "param", "cloud_storage"]
SeverityLevel = Literal["info", "low", "medium", "high", "critical"]
ConfidenceLevel = Literal["low", "medium", "high"]
ErrorStage = Literal["validate", "exec", "parse"]

# Global registry for storing tool and workflow endpoints
_TOOL_REGISTRY: dict[str, dict[str, Any]] = {}
_WORKFLOW_REGISTRY: dict[str, dict[str, Any]] = {}


# Unified API Schema Documentation
"""
UNIFIED BUG BOUNTY API SCHEMA

This module implements a consistent API contract for all bug bounty tools and workflows.

SUCCESS RESPONSE SCHEMA:
{
    "success": true,
    "result": {
        "tool": "<tool_name>",           # Name of the tool that was executed
        "version": "<version_string>",   # Optional: Tool version (if available)
        "params": {...},                 # Parameters that were used for execution
        "started_at": "ISO8601",         # Execution start time
        "ended_at": "ISO8601",           # Execution end time
        "duration_ms": 1234,             # Execution duration in milliseconds
        "findings": [                    # Array of discovered findings
            {
                "type": "<finding_type>",     # One of: subdomain|port|vuln|endpoint|
                                            # param|cloud_storage
                "target": "<host_or_url>",    # Target host/URL for this finding
                "evidence": {...},            # Tool-specific evidence data
                "severity": "<severity>",     # One of: info|low|medium|high|critical
                "confidence": "<confidence>", # One of: low|medium|high
                "tags": ["tag1", "tag2"],    # Array of relevant tags
                "raw_ref": "<reference_id>"   # Reference to raw tool output
            }
        ],
        "stats": {                       # Execution statistics
            "findings": 42,              # Total number of findings
            "dupes": 3,                  # Number of duplicate findings removed
            "payload_bytes": 1048576     # Size of tool output in bytes
        }
    }
}

ERROR RESPONSE SCHEMA:
{
    "success": false,
    "error": "<error_message>",     # Human-readable error description
    "stage": "<error_stage>",       # One of: validate|exec|parse
    "details": {...}                # Optional additional error details
}

FINDING TYPES:
- subdomain: DNS subdomain discovery
- port: Network port/service discovery
- vuln: Security vulnerability detection
- endpoint: API/web endpoint discovery
- param: Parameter/input discovery
- cloud_storage: Cloud storage bucket/service discovery

SEVERITY LEVELS:
- info: Informational findings
- low: Low severity issues
- med: Medium severity issues
- high: High severity issues
- critical: Critical security issues

CONFIDENCE LEVELS:
- low: Low confidence in finding accuracy
- med: Medium confidence in finding accuracy
- high: High confidence in finding accuracy

ERROR STAGES:
- validate: Error during input validation
- exec: Error during tool execution
- parse: Error during output parsing
"""


def validate_required_fields(required_fields: list[str]):
    """Decorator factory to validate required JSON fields."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            data = request.get_json()
            if not data:
                error_response, status_code = create_error_response(
                    "JSON data is required",
                    stage="validate",
                    details={"required_fields": required_fields},
                    status_code=400,
                )
                return jsonify(error_response), status_code

            for field in required_fields:
                if field not in data:
                    error_response, status_code = create_error_response(
                        f"{field.title()} is required",
                        stage="validate",
                        details={
                            "missing_field": field,
                            "required_fields": required_fields,
                        },
                        status_code=400,
                    )
                    return jsonify(error_response), status_code

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
            # Log and return detailed error for local debugging
            logger.error(f"Error in {func.__name__}: {str(e)}")
            return jsonify(
                {
                    "success": False,
                    "error": f"Server error: {str(e)}",
                    "stage": "exec",
                    "details": {"function": func.__name__},
                }
            ), 500

    return wrapper


def create_error_response(
    error_message: str,
    stage: ErrorStage = "exec",
    details: dict[str, Any] | None = None,
    status_code: int = 500,
) -> tuple[dict[str, Any], int]:
    """Create a standardized error response following the unified schema.

    Args:
        error_message: Human-readable error description
        stage: Stage where error occurred (validate|exec|parse)
        details: Optional additional error details
        status_code: HTTP status code

    Returns:
        Tuple of (error_response_dict, status_code)
    """
    return {
        "success": False,
        "error": error_message,
        "stage": stage,
        "details": details or {},
    }, status_code


def format_response(
    tool_name: str | None = None, params: dict[str, Any] | None = None
) -> Callable:
    """Create a unified response wrapper for bug bounty tools following standard.

    This function wraps tool execution results in the unified API schema format,
    providing consistent response structure across all bug bounty tools.

    Args:
        tool_name: Name of the tool being executed (auto-detected if None)
        params: Parameters used for tool execution (extracted from request if None)

    Returns:
        Decorator function that wraps tool responses in unified schema

    Usage:
        @format_response()
        def execute_nmap():
            # Tool execution logic here
            return {
                'findings': [...],
                'stats': {...},
                'version': '7.94'  # optional
            }

    The decorated function should return a dict with:
        - findings: List of finding objects
        - stats: Statistics dict with findings/dupes/payload_bytes counts
        - version: Optional tool version string
        - Any other tool-specific data goes in the response
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Record start time
            start_time = time.time()
            started_at = datetime.now(UTC).isoformat()

            # Execute the wrapped function
            result = func(*args, **kwargs)

            # If it's already a Flask response or error tuple, return as-is
            if hasattr(result, "status_code"):
                return result
            if isinstance(result, tuple) and len(result) == 2:
                response_obj, status_code = result
                if hasattr(response_obj, "status_code") or isinstance(
                    response_obj, dict
                ):
                    return result

            # Record end time and calculate duration
            end_time = time.time()
            ended_at = datetime.now(UTC).isoformat()
            duration_ms = int((end_time - start_time) * 1000)

            # Extract tool name from function name if not provided
            detected_tool_name = tool_name or func.__name__.replace("execute_", "")

            # Extract params from request if not provided
            request_params = params
            if request_params is None:
                try:
                    request_params = request.get_json() or {}
                except Exception:
                    request_params = {}

            # Handle different result formats
            if isinstance(result, dict):
                findings = result.get("findings", [])
                stats = result.get("stats", {})
                version = result.get("version")

                # Ensure stats has required fields
                if "findings" not in stats:
                    stats["findings"] = len(findings)
                if "dupes" not in stats:
                    stats["dupes"] = 0
                if "payload_bytes" not in stats:
                    stats["payload_bytes"] = 0

            else:
                # Legacy format - assume result is findings list
                findings = result if isinstance(result, list) else []
                stats = {"findings": len(findings), "dupes": 0, "payload_bytes": 0}
                version = None

            # Build unified response
            unified_result = {
                "tool": detected_tool_name,
                "params": request_params,
                "started_at": started_at,
                "ended_at": ended_at,
                "duration_ms": duration_ms,
                "findings": findings,
                "stats": stats,
            }

            # Add version if available
            if version:
                unified_result["version"] = version

            return jsonify({"success": True, "result": unified_result})

        return wrapper

    return decorator


def legacy_format_response(success_key: str = "result"):
    """Legacy decorator factory for backward compatibility.

    Use format_response() for new tools following the unified schema.
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            result = func(*args, **kwargs)
            # If it's already a Flask response, return as-is
            if hasattr(result, "status_code"):
                return result
            # If it's a tuple (response, status_code), return as-is
            if isinstance(result, tuple) and len(result) == 2:
                response_obj, status_code = result
                if hasattr(response_obj, "status_code"):
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
    """Decorator to register tool execution endpoints.

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
        decorated_func = format_response(tool_name)(decorated_func)

        _TOOL_REGISTRY[tool_name] = {
            "function": decorated_func,
            "methods": methods,
            "endpoint": endpoint,
            "required_fields": required_fields,
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
    """Decorator to register workflow creation endpoints.

    Args:
        name: Workflow name (defaults to function name without prefixes/suffixes)
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
        decorated_func = legacy_format_response("workflow")(decorated_func)

        _WORKFLOW_REGISTRY[workflow_name] = {
            "function": decorated_func,
            "methods": methods,
            "endpoint": endpoint,
            "required_fields": required_fields,
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
            name: {
                "endpoint": config["endpoint"],
                "methods": config["methods"],
                "required_fields": config.get("required_fields", []),
            }
            for name, config in _TOOL_REGISTRY.items()
        },
        "workflows": {
            name: {
                "endpoint": config["endpoint"],
                "methods": config["methods"],
                "required_fields": config.get("required_fields", []),
            }
            for name, config in _WORKFLOW_REGISTRY.items()
        },
    }


def create_finding(
    finding_type: FindingType,
    target: str,
    evidence: dict[str, Any],
    severity: SeverityLevel = "info",
    confidence: ConfidenceLevel = "medium",
    tags: list[str] | None = None,
    raw_ref: str | None = None,
) -> dict[str, Any]:
    """Create a standardized finding object following the unified schema.

    Args:
        finding_type: Type of finding (subdomain|port|vuln|endpoint|param|cloud_storage)
        target: Target host/URL for this finding
        evidence: Tool-specific evidence data
        severity: Severity level (info|low|medium|high|critical)
        confidence: Confidence level (low|medium|high)
        tags: Optional list of relevant tags
        raw_ref: Optional reference to raw tool output

    Returns:
        Dict representing a standardized finding object
    """
    return {
        "type": finding_type,
        "target": target,
        "evidence": evidence,
        "severity": severity,
        "confidence": confidence,
        "tags": tags or [],
        "raw_ref": raw_ref,
    }


def create_stats(
    findings_count: int | None = None,
    dupes_count: int = 0,
    payload_bytes: int = 0,
    findings_list: list[dict] | None = None,
) -> dict[str, Any]:
    """Create a standardized stats object following the unified schema.

    Args:
        findings_count: Total number of findings (auto-calculated if None)
        dupes_count: Number of duplicate findings removed
        payload_bytes: Size of tool output in bytes
        findings_list: Optional findings list to auto-calculate count

    Returns:
        Dict representing standardized stats object
    """
    if findings_count is None and findings_list is not None:
        findings_count = len(findings_list)
    elif findings_count is None:
        findings_count = 0

    return {
        "findings": findings_count,
        "dupes": dupes_count,
        "payload_bytes": payload_bytes,
    }


# Export important types and functions for use by tools
__all__ = [
    "FindingType",
    "SeverityLevel",
    "ConfidenceLevel",
    "ErrorStage",
    "tool",
    "workflow",
    "format_response",
    "legacy_format_response",
    "create_error_response",
    "create_finding",
    "create_stats",
    "validate_required_fields",
    "handle_exceptions",
    "register_all_endpoints",
    "get_registered_endpoints",
]
