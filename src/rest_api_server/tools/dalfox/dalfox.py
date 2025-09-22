"""dalfox tool implementation."""

import logging

from flask import request

from src.rest_api_server.utils.commands import execute_command
from src.rest_api_server.utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_dalfox_params(data):
    """Extract and validate dalfox parameters from request data."""
    # Check for aggressive mode
    aggressive = data.get("aggressive", False)

    # Base parameters
    base_params = {
        "url": data.get("url", data.get("target", "")),
        "blind": data.get("blind", False),
        "deep": data.get("deep", False),
        "mining": data.get("mining", False),
        "workers": data.get("workers", 25),
        "delay": data.get("delay", 1),
        "timeout": data.get("timeout", 10),
        "waf_evasion": data.get("waf_evasion", False),
        "follow_redirects": data.get("follow_redirects", False),
        "custom_payload": data.get("custom_payload", ""),
        "additional_args": data.get("additional_args", ""),
        "pipe_mode": data.get("pipe_mode", False),
        "mining_dom": data.get("mining_dom", False),
        "mining_dict": data.get("mining_dict", False),
        "method": data.get("method", "GET"),
        "headers": data.get("headers", ""),
        "cookies": data.get("cookies", ""),
    }

    # Apply aggressive preset if requested
    # Apply aggressive preset if requested (local implementation)
    if aggressive:
        # Dalfox aggressive preset
        base_params.update(
            {
                "blind": True,
                "deep": True,
                "mining": True,
                "workers": 100,
                "delay": 0,
                "timeout": 30,
                "waf_evasion": True,
                "follow_redirects": True,
                "mining_dom": True,
                "mining_dict": True,
            }
        )
    return base_params


def _build_dalfox_command(params):
    """Build dalfox command from parameters."""
    cmd_parts = ["dalfox"]

    # Build dalfox command
    if params["pipe_mode"]:
        cmd_parts.append("pipe")
    else:
        cmd_parts.extend(["url", params["url"]])

    # Add dalfox-specific parameters
    if params["blind"]:
        cmd_parts.append("--blind")

    if params["mining_dom"]:
        cmd_parts.append("--mining-dom")

    if params["mining_dict"]:
        cmd_parts.append("--mining-dict")

    if params["custom_payload"]:
        cmd_parts.extend(["--custom-payload", params["custom_payload"]])

    if params["workers"] != 100:
        cmd_parts.extend(["--worker", str(params["workers"])])

    if params["method"] != "GET":
        cmd_parts.extend(["--method", params["method"]])

    if params["headers"]:
        cmd_parts.extend(["--header", params["headers"]])

    if params["cookies"]:
        cmd_parts.extend(["--cookie", params["cookies"]])

    if params["timeout"] != 10:
        cmd_parts.extend(["--timeout", str(params["timeout"])])

    # Handle additional arguments
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_dalfox_result(execution_result, params, command):
    """Parse dalfox execution result and format response."""
    return {
        "tool": "dalfox",
        "target": params["url"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
        "parameters": {
            "url": params["url"],
            "pipe_mode": params["pipe_mode"],
            "blind": params["blind"],
            "mining_dom": params["mining_dom"],
            "mining_dict": params["mining_dict"],
            "custom_payload": params["custom_payload"],
            "workers": params["workers"],
            "method": params["method"],
            "headers": params["headers"],
            "cookies": params["cookies"],
            "timeout": params["timeout"],
            "additional_args": params["additional_args"],
        },
    }


@tool(required_fields=["url"])
def execute_dalfox():
    """Execute Dalfox for XSS vulnerability scanning."""
    data = request.get_json()
    params = _extract_dalfox_params(data)

    logger.info(f"Executing Dalfox XSS scan on {params['url']}")

    command = _build_dalfox_command(params)
    execution_result = execute_command(
        command, timeout=600
    )  # 10 minutes timeout for XSS scanning

    logger.info(f"Dalfox XSS scan completed for {params['url']}")
    return _parse_dalfox_result(execution_result, params, command)
