import logging

from flask import request

from utils.commands import execute_command
from utils.registry import tool

logger = logging.getLogger(__name__)


def _extract_subfinder_params(data):
    """Extract and validate subfinder parameters from request data."""
    return {
        "domain": data["domain"],
        "silent": data.get("silent", True),
        "all_sources": data.get("all_sources", False),
        "sources": data.get("sources"),
        "threads": data.get("threads", 10),
        "additional_args": data.get("additional_args"),
    }


def _build_subfinder_command(params):
    """Build subfinder command from parameters."""
    cmd_parts = ["subfinder", "-d", params["domain"]]

    if params["silent"]:
        cmd_parts.append("-silent")
    if params["all_sources"]:
        cmd_parts.append("-all")
    if params["sources"]:
        cmd_parts.extend(["-sources", params["sources"]])
    if params["threads"] != 10:
        cmd_parts.extend(["-t", str(params["threads"])])
    if params["additional_args"]:
        cmd_parts.extend(params["additional_args"].split())

    return " ".join(cmd_parts)


def _parse_subfinder_result(execution_result, params, command):
    """Parse subfinder execution result and format response."""
    return {
        "tool": "subfinder",
        "target": params["domain"],
        "command": command,
        "success": execution_result["success"],
        "stdout": execution_result.get("stdout", ""),
        "stderr": execution_result.get("stderr", ""),
        "return_code": execution_result.get("return_code", 0),
    }


@tool(required_fields=["domain"])
def execute_subfinder():
    """Execute Subfinder for passive subdomain enumeration."""
    data = request.get_json()
    params = _extract_subfinder_params(data)

    logger.info(f"Executing Subfinder on {params['domain']}")

    command = _build_subfinder_command(params)
    execution_result = execute_command(command, timeout=300)

    return _parse_subfinder_result(execution_result, params, command)
